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
pub enum Web3Procedures<T: web3::Transport + Send + Sync> {
    Web3SignTransaction(Web3SignTransaction<T>),
    Web3Address(Web3Address<T>),
}

impl<T> Procedure for Web3Procedures<T>
where
    T: web3::Transport + Send + Sync,
{
    type Output = ProcedureOutput;

    fn execute<R: Runner>(self, runner: &R) -> Result<Self::Output, ProcedureError> {
        use Web3Procedures::*;

        match self {
            Web3SignTransaction(proc) => proc.execute(runner).map(|o| o.into()),
            Web3Address(proc) => proc.execute(runner).map(|o| o.into()),
        }
    }
}

impl<T> Web3Procedures<T>
where
    T: web3::Transport + Send + Sync,
{
    pub(crate) fn input(&self) -> Option<Location> {
        match self {
            Web3Procedures::Web3SignTransaction(Web3SignTransaction { private_key: input, .. })
            | Web3Procedures::Web3Address(Web3Address { private_key: input, .. }) => Some(input.clone()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Web3SignTransaction<T: web3::Transport + Send + Sync> {
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
pub struct Web3Address<T: web3::Transport + Send + Sync> {
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

        Ok(address.as_bytes().to_vec())
    }

    fn source(&self) -> [Location; 1] {
        [self.private_key.clone()]
    }
}

impl<T> Procedure for Web3SignTransaction<T>
where
    T: web3::Transport + Send + Sync,
{
    type Output = ProcedureOutput;

    fn execute<R: Runner>(self, runner: &R) -> Result<Self::Output, ProcedureError> {
        Ok(self.exec(runner)?.into())
    }
}

impl<T> Procedure for Web3Address<T>
where
    T: web3::Transport + Send + Sync,
{
    type Output = ProcedureOutput;

    fn execute<R: Runner>(self, runner: &R) -> Result<Self::Output, ProcedureError> {
        Ok(self.exec(runner)?.into())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTx {
    pub message_hash: H256,
    pub v: u64,
    pub r: H256,
    pub s: H256,
    pub raw_transaction: Vec<u8>,
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
            raw_transaction: tx.raw_transaction.0,
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
            raw_transaction: tx.raw_transaction.into(),
            transaction_hash: tx.transaction_hash,
        }
    }
}

impl<T> From<Web3SignTransaction<T>> for Web3Procedures<T>
where
    T: web3::Transport + Send + Sync,
{
    fn from(tx: Web3SignTransaction<T>) -> Web3Procedures<T> {
        Web3Procedures::Web3SignTransaction(tx)
    }
}

impl<T> From<Web3Address<T>> for Web3Procedures<T>
where
    T: web3::Transport + Send + Sync,
{
    fn from(tx: Web3Address<T>) -> Web3Procedures<T> {
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

#[cfg(test)]
mod web3_tests {
    use super::*;
    use jsonrpc_core::{Call, Value};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use web3::futures::future::{self, Ready};
    use web3::helpers;
    use web3::{error::Error, BatchTransport};
    use web3::{
        types::{Transaction, U256},
        RequestId, Transport,
    };

    type Requests = Vec<(String, Vec<Value>)>;

    #[derive(Debug, Default)]
    struct Inner {
        asserted: usize,
        requests: Requests,
        responses: VecDeque<Value>,
    }

    /// Test transport
    #[derive(Debug, Default, Clone)]
    pub struct TestTransport {
        inner: Arc<Mutex<Inner>>,
    }

    impl Transport for TestTransport {
        type Out = Ready<Result<Value, Error>>;

        fn prepare(&self, method: &str, params: Vec<Value>) -> (RequestId, Call) {
            let request = helpers::build_request(1, method, params.clone());
            let mut inner = self.inner.lock().unwrap();
            inner.requests.push((method.into(), params));
            (inner.requests.len(), request)
        }

        fn send(&self, id: RequestId, request: Call) -> Self::Out {
            let mut inner = self.inner.lock().unwrap();
            match inner.responses.pop_front() {
                Some(response) => future::ok(response),
                None => {
                    println!("Unexpected request (id: {:?}): {:?}", id, request);
                    future::err(Error::Unreachable)
                }
            }
        }
    }

    impl BatchTransport for TestTransport {
        type Batch = Ready<Result<Vec<Result<Value, Error>>, Error>>;

        fn send_batch<T>(&self, requests: T) -> Self::Batch
        where
            T: IntoIterator<Item = (RequestId, Call)>,
        {
            let mut requests: Vec<_> = requests.into_iter().collect();

            let (id, call) = match requests.pop() {
                Some(request) => request,
                None => return future::err(Error::Unreachable),
            };

            let responses = match self
                .send(id, call)
                .into_inner()
                .ok()
                .and_then(|value| value.as_array().cloned())
            {
                Some(array) => array.into_iter(),
                None => {
                    println!("Response should return a list of values");
                    return future::err(Error::Unreachable);
                }
            };
            future::ok(responses.map(Ok).collect())
        }
    }

    impl TestTransport {
        pub fn new() -> Self {
            Default::default()
        }

        pub fn add_response(&mut self, value: Value) {
            let mut inner = self.inner.lock().unwrap();
            inner.responses.push_back(value);
        }

        pub fn assert_request(&mut self, method: &str, params: &[Value]) {
            let mut inner = self.inner.lock().unwrap();
            let idx = inner.asserted;
            inner.asserted += 1;

            let (m, p) = inner.requests.get(idx).expect("Expected result.").clone();
            assert_eq!(&m, method);
            assert_eq!(&p[..], params);
        }

        pub fn assert_no_more_requests(&self) {
            let inner = self.inner.lock().unwrap();
            assert_eq!(
                inner.asserted,
                inner.requests.len(),
                "Expected no more requests, got: {:?}",
                &inner.requests[inner.asserted..]
            );
        }
    }

    #[tokio::test]
    async fn test_web3_procedures() {
        use serde_json::json;

        let mut transport = TestTransport::new();
        let web3 = web3::Web3::new(transport.clone());
        let accounts = web3.accounts();
        let chain_id = 77777;

        let stronghold = crate::Stronghold::default();
        let client: Client = stronghold.create_client(b"client_path").unwrap();

        let keypair_location = Location::generic("Secp256k1", "keypair");

        let gen_key = crate::procedures::GenerateKey {
            ty: crate::procedures::KeyType::Secp256k1,
            output: keypair_location.clone(),
        };

        client.execute_procedure(gen_key).unwrap();

        let proc_address = Web3Address {
            accounts: accounts.clone(),
            private_key: keypair_location.clone(),
        };

        let res = client.execute_web3_procedure(proc_address).unwrap();
        let res: Vec<u8> = res.into();
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(&res);

        let from = Address::from(&bytes);
        let to = "0x0123456789012345678901234567890123456789";
        let to = Address::from_str(to).unwrap();
        let hash = "0x6752d1a9ccd104cb4bb42cfd6cd5cef957fd0e9411198f8d8daf35e71bb441ba";
        let hash = web3::types::H256::from_str(hash).unwrap();

        transport.add_response(json!(hash));

        let tx_params = web3::types::TransactionParameters {
            nonce: Some(U256::from(42)),
            to: Some(to),
            gas_price: Some(U256::from(2)),
            gas: 1.into(),
            value: U256::from(28),
            data: web3::types::Bytes(vec![0x13, 0x37]),
            chain_id: Some(77777),
            transaction_type: None,
            access_list: None,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
        };

        let web3signedtx = Web3SignTransaction {
            accounts: accounts,
            tx: tx_params,
            private_key: keypair_location,
        };

        let res = client.execute_web3_procedure(web3signedtx).unwrap();
        let signed_tx: SignedTx = res.try_into().unwrap();
        let signed_tx: SignedTransaction = signed_tx.into();

        println!("{:?}", signed_tx);
    }
}
