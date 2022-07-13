// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use super::types::*;

use crate::{derive_record_id, derive_vault_id, Client, ClientError, Location};
use serde::{Deserialize, Serialize};

use crypto::signatures::secp256k1;

use engine::runtime::memories::buffer::{Buffer, Ref};

use stronghold_utils::GuardDebug;
use web3::{
    api::Accounts,
    signing::{Key, Signature, SigningError},
    types::{Address, Bytes, SignedTransaction, H256},
};

#[derive(Clone, GuardDebug)]
pub enum Web3Procedures<T: web3::Transport + Send + Sync = web3::transports::Http> {
    Web3SignTransaction(Web3SignTransaction<T>),
    Web3Address(Web3Address<T>),
}

impl Procedure for Web3Procedures<web3::transports::Http> {
    type Output = Vec<u8>;

    fn execute<R: Runner>(self, runner: &R) -> Result<Self::Output, ProcedureError> {
        use Web3Procedures::*;

        match self {
            Web3SignTransaction(proc) => proc.execute(runner).map(|o| o.into()),
            Web3Address(proc) => proc.execute(runner).map(|o| o.into()),
        }
    }
}

impl Web3Procedures<web3::transports::Http> {
    pub(crate) fn input(&self) -> Option<Location> {
        match self {
            Web3Procedures::Web3SignTransaction(Web3SignTransaction { private_key: input, .. })
            | Web3Procedures::Web3Address(Web3Address { private_key: input, .. }) => Some(input.clone()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Web3SignTransaction<T: web3::Transport + Send + Sync = web3::transports::Http> {
    accounts: Accounts<T>,
    tx: web3::types::TransactionParameters,
    private_key: Location,
}

impl<T> UseSecret<1> for Web3SignTransaction<T>
where
    T: web3::Transport + Send + Sync,
{
    type Output = Vec<u8>;

    fn use_secret(self, guard: [Buffer<u8>; 1]) -> Result<Self::Output, FatalProcedureError> {
        let pk = secp256k1::SecretKey::from_slice(&guard[0].borrow())?;
        let pk_ref = SecretKeyRef(&pk);

        let signed_tx = futures::executor::block_on(self.accounts.sign_transaction(self.tx, pk_ref))
            .map_err(|e| FatalProcedureError::from(format!("Failed to sign tx: {:?}", e.to_string())))?;

        let tx_ref: SignedTx = signed_tx.into();

        bincode::serialize(&tx_ref).map_err(|_| FatalProcedureError::from("Unable to serialize transaction".to_owned()))
    }

    fn source(&self) -> [Location; 1] {
        [self.private_key.clone()]
    }
}

#[derive(Debug, Clone)]
pub struct Web3Address<T: web3::Transport + Send + Sync = web3::transports::Http> {
    accounts: Accounts<T>,
    private_key: Location,
}

impl<T> UseSecret<1> for Web3Address<T>
where
    T: web3::Transport + Send + Sync,
{
    type Output = Vec<u8>;

    fn use_secret(self, guard: [Buffer<u8>; 1]) -> Result<Self::Output, FatalProcedureError> {
        let pk = secp256k1::SecretKey::from_slice(&guard[0].borrow())?;
        let pk_ref = SecretKeyRef(&pk);
        let address = pk_ref.address();

        bincode::serialize(&address).map_err(|_| FatalProcedureError::from("Unable to serialize address".to_owned()))
    }

    fn source(&self) -> [Location; 1] {
        [self.private_key.clone()]
    }
}

impl Procedure for Web3SignTransaction<web3::transports::Http> {
    type Output = Vec<u8>;

    fn execute<R: Runner>(self, runner: &R) -> Result<Self::Output, ProcedureError> {
        self.exec(runner)
    }
}

impl Procedure for Web3Address<web3::transports::Http> {
    type Output = Vec<u8>;

    fn execute<R: Runner>(self, runner: &R) -> Result<Self::Output, ProcedureError> {
        self.exec(runner)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTx {
    pub message_hash: H256,
    pub v: u64,
    pub r: H256,
    pub s: H256,
    pub raw_transaction: Bytes,
    pub transaction_hash: H256,
}

struct SecretKeyRef<'a>(&'a secp256k1::SecretKey);

impl<'a> Key for SecretKeyRef<'a> {
    fn sign(&self, message: &[u8], chain_id: Option<u64>) -> Result<Signature, SigningError> {
        let (signature, recovery_id) = self.0.sign(
            message[0..32]
                .try_into()
                .expect("secp256k1 message must contain exactly 32 bytes"),
        );

        let standard_v = recovery_id.as_u8() as u64;
        let v = if let Some(chain_id) = chain_id {
            // When signing with a chain ID, add chain replay protection.
            standard_v + 35 + chain_id * 2
        } else {
            // Otherwise, convert to 'Electrum' notation.
            standard_v + 27
        };
        let signature = signature.to_bytes();
        let r = H256::from_slice(&signature[..32]);
        let s = H256::from_slice(&signature[32..]);

        Ok(Signature { v, r, s })
    }

    fn sign_message(&self, message: &[u8]) -> Result<Signature, SigningError> {
        let (signature, recovery_id) = self.0.sign(
            message[0..32]
                .try_into()
                .expect("secp256k1 message must contain exactly 32 bytes"),
        );

        let v = recovery_id.as_u8() as u64;
        let signature = signature.to_bytes();
        let r = H256::from_slice(&signature[..32]);
        let s = H256::from_slice(&signature[32..]);

        Ok(Signature { v, r, s })
    }

    fn address(&self) -> Address {
        let public_key = self.0.public_key();
        let public_key = public_key.to_bytes();

        debug_assert_eq!(public_key[0], 0x04);
        let hash = keccak256(&public_key[1..]);

        Address::from_slice(&hash[12..])
    }
}

fn keccak256(bytes: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    hasher.finalize(&mut output);
    output
}

impl From<SignedTransaction> for SignedTx {
    fn from(tx: SignedTransaction) -> SignedTx {
        SignedTx {
            message_hash: tx.message_hash,
            v: tx.v,
            r: tx.r,
            s: tx.s,
            raw_transaction: tx.raw_transaction,
            transaction_hash: tx.transaction_hash,
        }
    }
}

impl From<SignedTx> for SignedTransaction {
    fn from(tx: SignedTx) -> SignedTransaction {
        SignedTransaction {
            message_hash: tx.message_hash,
            v: tx.v,
            r: tx.r,
            s: tx.s,
            raw_transaction: tx.raw_transaction,
            transaction_hash: tx.transaction_hash,
        }
    }
}

impl From<Web3SignTransaction<web3::transports::Http>> for Web3Procedures {
    fn from(tx: Web3SignTransaction<web3::transports::Http>) -> Web3Procedures {
        Web3Procedures::Web3SignTransaction(tx)
    }
}

impl From<Web3Address<web3::transports::Http>> for Web3Procedures {
    fn from(tx: Web3Address<web3::transports::Http>) -> Web3Procedures {
        Web3Procedures::Web3Address(tx)
    }
}

impl TryFrom<ProcedureOutput> for SignedTx {
    type Error = FatalProcedureError;

    fn try_from(value: ProcedureOutput) -> Result<Self, Self::Error> {
        bincode::deserialize(&value.0)
            .map_err(|e| FatalProcedureError::from(format!("Contents can't be deserialized by bincode: {:?}", e)))
    }
}
