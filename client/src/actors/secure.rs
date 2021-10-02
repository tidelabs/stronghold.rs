// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Secure Actor module
//!
//! The secure actor runs as service, isolates contained data, and synchronizes
//! across multiple accesses.

#![allow(clippy::type_complexity)]

use crate::internals;
pub use crate::{
    actors::{GetSnapshot, Registry},
    internals::Provider,
    state::{key_store::KeyStore, secure::SecureClient, snapshot::Snapshot},
    utils::StatusMessage,
    ResultMessage,
};
use actix::{Actor, ActorContext, Context, Handler, Message, Supervised};
use web3::{
    api::Accounts,
    signing::{Key as Web3Key, Signature, SigningError},
    types::{Address as Web3AddressType, SignedTransaction, TransactionParameters, H256},
};

use crypto::{
    keys::{
        bip39,
        slip10::{self, Chain, Curve, Seed},
    },
    signatures::{
        ed25519,
        secp256k1::{
            PublicKey as Secp256k1PublicKeyValue, RecoveryId as Secp256k1RecoveryId, SecretKey as Secp256k1SecretKey,
            Signature as Secp256k1Signature, PUBLIC_KEY_LENGTH as SECP256K1_PUBLIC_KEY_LENGTH,
            SECRET_KEY_LENGTH as SECP256K1_SECRET_KEY_LENGTH, SIGNATURE_LENGTH as SECP256K1_SIGNATURE_LENGTH,
        },
        sr25519::{
            DeriveJunction as Sr25519DeriveJunction, KeyPair as Sr25519KeyPair, PublicKey as Sr25519PublicKeyValue,
            Signature as Sr25519Signature, PUBLIC_KEY_LENGTH as SR25519_PUBLIC_KEY_LENGTH,
            SIGNATURE_LENGTH as SR25519_SIGNATURE_LENGTH,
        },
    },
    utils::rand::fill,
};
use engine::{
    store::Cache,
    vault::{ClientId, DbView, Key, RecordHint, RecordId, VaultId},
};
use std::{
    cell::Cell,
    collections::HashMap,
    convert::{TryFrom, TryInto},
    ops::Deref,
    rc::Rc,
};

use self::procedures::CallProcedure;
// sub-modules re-exports
pub use self::procedures::ProcResult;

/// Store typedef on `engine::store::Cache`
pub type Store = Cache<Vec<u8>, Vec<u8>>;

use stronghold_utils::GuardDebug;
use thiserror::Error as DeriveError;

#[derive(DeriveError, Debug)]
pub enum VaultError {
    #[error("Vault does not exist")]
    NotExisting,

    #[error("Failed to revoke record, vault does not exist")]
    RevocationError,

    #[error("Failed to collect gargabe, vault does not exist")]
    GarbageCollectError,

    #[error("Failed to get list, vault does not exist")]
    ListError,

    #[error("Failed to access Vault")]
    AccessError,
}

#[derive(DeriveError, Debug)]
pub enum StoreError {
    #[error("Unable to read from store")]
    NotExisting,
}

#[derive(DeriveError, Debug)]
pub enum SnapshotError {
    #[error("No snapshot present for client id ({0})")]
    NoSnapshotPresent(String),
}

/// Message types for [`SecureClientActor`]
pub mod messages {

    use super::*;
    use crate::{internals, Location};
    use serde::{Deserialize, Serialize};
    use std::time::Duration;

    #[derive(Clone, GuardDebug)]
    pub struct Terminate;

    impl Message for Terminate {
        type Result = ();
    }

    #[derive(Clone, GuardDebug)]
    pub struct ReloadData {
        pub id: ClientId,
        pub data: Box<(
            HashMap<VaultId, Key<internals::Provider>>,
            DbView<internals::Provider>,
            Store,
        )>,
    }

    impl Message for ReloadData {
        type Result = ();
    }

    #[derive(Clone, GuardDebug, Serialize, Deserialize)]
    pub struct CreateVault {
        pub location: Location,
    }

    impl Message for CreateVault {
        type Result = ();
    }

    #[derive(Clone, GuardDebug, Serialize, Deserialize)]
    pub struct WriteToVault {
        pub location: Location,

        pub payload: Vec<u8>,
        pub hint: RecordHint,
    }

    impl Message for WriteToVault {
        type Result = Result<(), anyhow::Error>;
    }

    #[derive(Clone, GuardDebug, Serialize, Deserialize)]
    pub struct RevokeData {
        pub location: Location,
    }

    impl Message for RevokeData {
        type Result = Result<(), anyhow::Error>;
    }

    #[derive(Clone, GuardDebug, Serialize, Deserialize)]
    pub struct GarbageCollect {
        pub location: Location,
    }

    impl Message for GarbageCollect {
        type Result = Result<(), anyhow::Error>;
    }

    #[derive(Clone, GuardDebug, Serialize, Deserialize)]
    pub struct ListIds {
        pub vault_path: Vec<u8>,
    }

    impl Message for ListIds {
        type Result = Result<Vec<(RecordId, RecordHint)>, anyhow::Error>;
    }

    #[derive(Clone, GuardDebug, Serialize, Deserialize)]
    pub struct CheckRecord {
        pub location: Location,
    }

    impl Message for CheckRecord {
        type Result = bool;
    }

    #[derive(Clone, GuardDebug, Serialize, Deserialize)]
    pub struct ClearCache;

    impl Message for ClearCache {
        type Result = Result<(), anyhow::Error>;
    }

    #[derive(Clone, GuardDebug, Serialize, Deserialize)]
    pub struct CheckVault {
        pub vault_path: Vec<u8>,
    }

    impl Message for CheckVault {
        type Result = bool;
    }

    #[derive(Clone, GuardDebug, Serialize, Deserialize)]
    pub struct WriteToStore {
        pub location: Location,
        pub payload: Vec<u8>,
        pub lifetime: Option<Duration>,
    }

    impl Message for WriteToStore {
        type Result = Result<(), anyhow::Error>;
    }

    #[derive(Clone, GuardDebug, Serialize, Deserialize)]
    pub struct ReadFromStore {
        pub location: Location,
    }

    impl Message for ReadFromStore {
        type Result = Result<Vec<u8>, anyhow::Error>;
    }

    #[derive(Clone, GuardDebug, Serialize, Deserialize)]
    pub struct DeleteFromStore {
        pub location: Location,
    }

    impl Message for DeleteFromStore {
        type Result = Result<(), anyhow::Error>;
    }

    pub struct GetData {}

    impl Message for GetData {
        type Result = Result<
            Box<(
                HashMap<VaultId, Key<internals::Provider>>,
                DbView<internals::Provider>,
                Store,
            )>,
            anyhow::Error,
        >;
    }
}

pub mod procedures {

    use super::*;
    use crate::Location;
    use crypto::keys::slip10::ChainCode;
    use serde::{Deserialize, Serialize};
    use std::convert::TryInto;

    /// for old client (cryptographic) procedure calling
    #[derive(Clone, Serialize, Deserialize)]
    pub enum Procedure<T: web3::Transport + Send + Sync = web3::transports::Http> {
        /// Generate a raw SLIP10 seed of the specified size (in bytes, defaults to 64 bytes/512 bits) and store it in
        /// the `output` location
        ///
        /// Note that this does not generate a BIP39 mnemonic sentence and it's not possible to
        /// generate one: use `BIP39Generate` if a mnemonic sentence will be required.
        SLIP10Generate {
            output: Location,
            hint: RecordHint,
            size_bytes: Option<usize>,
        },
        /// Derive a SLIP10 child key from a seed or a parent key, store it in output location and
        /// return the corresponding chain code
        SLIP10Derive {
            chain: Chain,
            input: SLIP10DeriveInput,
            output: Location,
            hint: RecordHint,
        },
        /// Use a BIP39 mnemonic sentence (optionally protected by a passphrase) to create or recover
        /// a BIP39 seed and store it in the `output` location
        BIP39Recover {
            mnemonic: String,
            passphrase: Option<String>,
            output: Location,
            hint: RecordHint,
        },
        /// Generate a BIP39 seed and its corresponding mnemonic sentence (optionally protected by a
        /// passphrase) and store them in the `output` location
        BIP39Generate {
            passphrase: Option<String>,
            output: Location,
            hint: RecordHint,
        },
        /// Read a BIP39 seed and its corresponding mnemonic sentence (optionally protected by a
        /// passphrase) and store them in the `output` location
        BIP39MnemonicSentence { seed: Location },
        /// Derive an Ed25519 public key from the corresponding private key stored at the specified
        /// location
        Ed25519PublicKey { private_key: Location },
        /// Use the specified Ed25519 compatible key to sign the given message
        ///
        /// Compatible keys are any record that contain the desired key material in the first 32 bytes,
        /// in particular SLIP10 keys are compatible.
        Ed25519Sign { private_key: Location, msg: Vec<u8> },

        /// Derive a sr25519 child key from a sr25519 key pair and store it in output location.
        Sr25519Derive {
            chain: Vec<crypto::signatures::sr25519::DeriveJunction>,
            input: Location,
            output: Location,
            hint: RecordHint,
        },
        /// Generate a sr25519 key pair and its corresponding mnemonic sentence or seed (optionally protected by a
        /// passphrase) and store them in the `output` location.
        Sr25519Generate {
            mnemonic_or_seed: Option<String>,
            passphrase: Option<String>,
            output: Location,
            hint: RecordHint,
        },
        /// Derive an Ed25519 public key from the corresponding keypair stored at the specified
        /// location.
        Sr25519PublicKey { keypair: Location },
        /// Use the specified Sr25519 keypair to sign the given message.
        Sr25519Sign { keypair: Location, msg: Vec<u8> },

        /// Generate a secp256k1 secret key and store them in the `output` location.
        Secp256k1Generate { output: Location, hint: RecordHint },
        /// Store a secp256k1 secret key in the `output` location.
        Secp256k1Store {
            key: Vec<u8>,
            output: Location,
            hint: RecordHint,
        },
        /// Gets the public key associated with the secp256k1 secret key stored on the given location.
        Secp256k1PublicKey { private_key: Location },
        /// Use the specified secp256k1 secret key to sign the given message.
        Secp256k1Sign { private_key: Location, msg: Box<[u8; 32]> },

        /// Sign transaction using web3 instance.
        #[serde(skip)]
        Web3SignTransaction {
            accounts: Accounts<T>,
            tx: TransactionParameters,
            private_key: Location,
        },
        #[serde(skip)]
        Web3Address {
            accounts: Accounts<T>,
            private_key: Location,
        },
    }

    #[derive(GuardDebug, Clone, Serialize, Deserialize)]
    #[serde(try_from = "SerdeProcResult")]
    #[serde(into = "SerdeProcResult")]
    pub enum ProcResult {
        /// Return from generating a `SLIP10` seed.
        SLIP10Generate(StatusMessage),
        /// Returns the public key derived from the `SLIP10Derive` call.
        SLIP10Derive(ResultMessage<ChainCode>),
        /// `BIP39Recover` return value.
        BIP39Recover(StatusMessage),
        /// `BIP39Generate` return value.
        BIP39Generate(StatusMessage),
        /// `BIP39MnemonicSentence` return value. Returns the mnemonic sentence for the corresponding seed.
        BIP39MnemonicSentence(ResultMessage<String>),
        /// Return value for `Ed25519PublicKey`. Returns an Ed25519 public key.
        Ed25519PublicKey(ResultMessage<[u8; crypto::signatures::ed25519::PUBLIC_KEY_LENGTH]>),
        /// Return value for `Ed25519Sign`. Returns an Ed25519 signature.
        Ed25519Sign(ResultMessage<[u8; crypto::signatures::ed25519::SIGNATURE_LENGTH]>),
        /// Returns the public key derived from the `Sr25519Derive` call.
        Sr25519Derive(StatusMessage),
        /// `Sr25519Generate` return value.
        Sr25519Generate(StatusMessage),
        /// Return value for `Sr25519PublicKey`. Returns an sr25519 public key.
        Sr25519PublicKey(ResultMessage<Sr25519PublicKeyValue>),
        /// Return value for `Sr25519Sign`. Returns an sr25519 signature.
        Sr25519Sign(ResultMessage<Sr25519Signature>),
        /// `Secp256k1Generate` return value.
        Secp256k1Generate(StatusMessage),
        /// `Secp256k1Store` return value.
        Secp256k1Store(StatusMessage),
        /// Return value for `Secp256k1PublicKey`. Returns a secp256k1 public key.
        Secp256k1PublicKey(ResultMessage<Secp256k1PublicKeyValue>),
        /// Return value for `Secp256k1Sign`. Returns a secp256k1 signature.
        Secp256k1Sign(ResultMessage<(Secp256k1Signature, Secp256k1RecoveryId)>),
        /// Return value for `Web3SignTransaction`. Returns the data for offline signed transaction.
        Web3SignTransaction(ResultMessage<SignedTransaction>),
        /// Return value for `Web3Address`. Returns the web3 address.
        Web3Address(ResultMessage<web3::types::Address>),

        /// Generic Error return message.
        Error(String),
    }

    impl TryFrom<SerdeProcResult> for ProcResult {
        type Error = crate::Error;

        fn try_from(serde_proc_result: SerdeProcResult) -> Result<Self, crate::Error> {
            match serde_proc_result {
                SerdeProcResult::SLIP10Generate(msg) => Ok(ProcResult::SLIP10Generate(msg)),
                SerdeProcResult::SLIP10Derive(msg) => Ok(ProcResult::SLIP10Derive(msg)),
                SerdeProcResult::BIP39Recover(msg) => Ok(ProcResult::BIP39Recover(msg)),
                SerdeProcResult::BIP39Generate(msg) => Ok(ProcResult::BIP39Generate(msg)),
                SerdeProcResult::BIP39MnemonicSentence(msg) => Ok(ProcResult::BIP39MnemonicSentence(msg)),
                SerdeProcResult::Ed25519PublicKey(msg) => {
                    let msg: ResultMessage<[u8; crypto::signatures::ed25519::PUBLIC_KEY_LENGTH]> = match msg {
                        ResultMessage::Ok(v) => ResultMessage::Ok(v.as_slice().try_into()?),
                        ResultMessage::Error(e) => ResultMessage::Error(e),
                    };
                    Ok(ProcResult::Ed25519PublicKey(msg))
                }
                SerdeProcResult::Ed25519Sign(msg) => {
                    let msg: ResultMessage<[u8; crypto::signatures::ed25519::SIGNATURE_LENGTH]> = match msg {
                        ResultMessage::Ok(v) => ResultMessage::Ok(v.as_slice().try_into()?),
                        ResultMessage::Error(e) => ResultMessage::Error(e),
                    };
                    Ok(ProcResult::Ed25519Sign(msg))
                }
                SerdeProcResult::Sr25519Derive(msg) => Ok(ProcResult::Sr25519Derive(msg)),
                SerdeProcResult::Sr25519Generate(msg) => Ok(ProcResult::Sr25519Generate(msg)),
                SerdeProcResult::Sr25519PublicKey(msg) => {
                    let msg: ResultMessage<Sr25519PublicKeyValue> = match msg {
                        ResultMessage::Ok(v) => {
                            ResultMessage::Ok(Sr25519PublicKeyValue::from_raw(v.as_slice().try_into()?))
                        }
                        ResultMessage::Error(e) => ResultMessage::Error(e),
                    };
                    Ok(ProcResult::Sr25519PublicKey(msg))
                }
                SerdeProcResult::Sr25519Sign(msg) => {
                    let msg: ResultMessage<Sr25519Signature> = match msg {
                        ResultMessage::Ok(v) => ResultMessage::Ok(Sr25519Signature::from_raw(v.as_slice().try_into()?)),
                        ResultMessage::Error(e) => ResultMessage::Error(e),
                    };
                    Ok(ProcResult::Sr25519Sign(msg))
                }
                SerdeProcResult::Secp256k1Generate(msg) => Ok(ProcResult::Secp256k1Generate(msg)),
                SerdeProcResult::Secp256k1Store(msg) => Ok(ProcResult::Secp256k1Store(msg)),
                SerdeProcResult::Secp256k1PublicKey(msg) => {
                    let msg: ResultMessage<Secp256k1PublicKeyValue> = match msg {
                        ResultMessage::Ok(v) => ResultMessage::Ok(
                            Secp256k1PublicKeyValue::from_bytes(v.as_slice().try_into()?)
                                .map_err(engine::Error::CryptoError)?,
                        ),
                        ResultMessage::Error(e) => ResultMessage::Error(e),
                    };
                    Ok(ProcResult::Secp256k1PublicKey(msg))
                }
                SerdeProcResult::Secp256k1Sign(r) => {
                    let msg: ResultMessage<(Secp256k1Signature, Secp256k1RecoveryId)> = match r {
                        ResultMessage::Ok((sig, recovery_id)) => ResultMessage::Ok((
                            Secp256k1Signature::from_bytes(sig.as_slice().try_into()?)
                                .map_err(engine::Error::CryptoError)?,
                            Secp256k1RecoveryId::from_u8(recovery_id).map_err(engine::Error::CryptoError)?,
                        )),
                        ResultMessage::Error(e) => ResultMessage::Error(e),
                    };
                    Ok(ProcResult::Secp256k1Sign(msg))
                }
                SerdeProcResult::Error(err) => Ok(ProcResult::Error(err)),
            }
        }
    }

    // Replaces arrays in ProcResult with vectors to derive Serialize/ Deserialize
    #[derive(Clone, Serialize, Deserialize)]
    enum SerdeProcResult {
        SLIP10Generate(StatusMessage),
        SLIP10Derive(ResultMessage<ChainCode>),
        BIP39Recover(StatusMessage),
        BIP39Generate(StatusMessage),
        BIP39MnemonicSentence(ResultMessage<String>),
        Ed25519PublicKey(ResultMessage<Vec<u8>>),
        Ed25519Sign(ResultMessage<Vec<u8>>),
        Sr25519Derive(StatusMessage),
        Sr25519Generate(StatusMessage),
        Sr25519PublicKey(ResultMessage<Vec<u8>>),
        Sr25519Sign(ResultMessage<Vec<u8>>),
        Secp256k1Generate(StatusMessage),
        Secp256k1Store(StatusMessage),
        Secp256k1PublicKey(ResultMessage<Vec<u8>>),
        Secp256k1Sign(ResultMessage<(Vec<u8>, u8)>),
        Error(String),
    }

    impl From<ProcResult> for SerdeProcResult {
        fn from(proc_result: ProcResult) -> Self {
            match proc_result {
                ProcResult::SLIP10Generate(msg) => SerdeProcResult::SLIP10Generate(msg),
                ProcResult::SLIP10Derive(msg) => SerdeProcResult::SLIP10Derive(msg),
                ProcResult::BIP39Recover(msg) => SerdeProcResult::BIP39Recover(msg),
                ProcResult::BIP39Generate(msg) => SerdeProcResult::BIP39Generate(msg),
                ProcResult::BIP39MnemonicSentence(msg) => SerdeProcResult::BIP39MnemonicSentence(msg),
                ProcResult::Ed25519PublicKey(msg) => {
                    let msg = match msg {
                        ResultMessage::Ok(slice) => ResultMessage::Ok(slice.to_vec()),
                        ResultMessage::Error(error) => ResultMessage::Error(error),
                    };
                    SerdeProcResult::Ed25519PublicKey(msg)
                }
                ProcResult::Ed25519Sign(msg) => {
                    let msg = match msg {
                        ResultMessage::Ok(slice) => ResultMessage::Ok(slice.to_vec()),
                        ResultMessage::Error(error) => ResultMessage::Error(error),
                    };
                    SerdeProcResult::Ed25519Sign(msg)
                }
                ProcResult::Sr25519Derive(msg) => SerdeProcResult::Sr25519Derive(msg),
                ProcResult::Sr25519Generate(msg) => SerdeProcResult::Sr25519Generate(msg),
                ProcResult::Sr25519PublicKey(msg) => {
                    let msg = match msg {
                        ResultMessage::Ok(public_key) => {
                            let raw: &[u8; SR25519_PUBLIC_KEY_LENGTH] = public_key.as_ref();
                            ResultMessage::Ok(raw.to_vec())
                        }
                        ResultMessage::Error(error) => ResultMessage::Error(error),
                    };
                    SerdeProcResult::Sr25519PublicKey(msg)
                }
                ProcResult::Sr25519Sign(msg) => {
                    let msg = match msg {
                        ResultMessage::Ok(signature) => {
                            let raw: &[u8; SR25519_SIGNATURE_LENGTH] = signature.as_ref();
                            ResultMessage::Ok(raw.to_vec())
                        }
                        ResultMessage::Error(error) => ResultMessage::Error(error),
                    };
                    SerdeProcResult::Sr25519Sign(msg)
                }
                ProcResult::Secp256k1Generate(msg) => SerdeProcResult::Secp256k1Generate(msg),
                ProcResult::Secp256k1Store(msg) => SerdeProcResult::Secp256k1Store(msg),
                ProcResult::Secp256k1PublicKey(msg) => {
                    let msg = match msg {
                        ResultMessage::Ok(public_key) => {
                            let raw: [u8; SECP256K1_PUBLIC_KEY_LENGTH] = public_key.to_bytes();
                            ResultMessage::Ok(raw.to_vec())
                        }
                        ResultMessage::Error(error) => ResultMessage::Error(error),
                    };
                    SerdeProcResult::Secp256k1PublicKey(msg)
                }
                ProcResult::Secp256k1Sign(msg) => {
                    let msg = match msg {
                        ResultMessage::Ok((signature, recovery_id)) => {
                            let raw: [u8; SECP256K1_SIGNATURE_LENGTH] = signature.to_bytes();
                            ResultMessage::Ok((raw.to_vec(), recovery_id.as_u8()))
                        }
                        ResultMessage::Error(error) => ResultMessage::Error(error),
                    };
                    SerdeProcResult::Secp256k1Sign(msg)
                }
                ProcResult::Web3SignTransaction(_msg) => panic!("unexpected `Web3SignTransaction` result"),
                ProcResult::Web3Address(_msg) => panic!("unexpected `Web3Address` result"),
                ProcResult::Error(err) => SerdeProcResult::Error(err),
            }
        }
    }

    #[derive(Clone, GuardDebug, Serialize, Deserialize)]
    pub struct CallProcedure<T: web3::Transport + Send + Sync = web3::transports::Http> {
        pub proc: Procedure<T>, // is procedure from client
    }

    impl<T: web3::Transport + Send + Sync> Message for CallProcedure<T> {
        type Result = Result<ProcResult, anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct SLIP10Generate {
        pub vault_id: VaultId,
        pub record_id: RecordId,
        pub hint: RecordHint,
        pub size_bytes: usize,
    }

    impl Message for SLIP10Generate {
        type Result = Result<crate::ProcResult, anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct SLIP10DeriveFromSeed {
        pub chain: Chain,
        pub seed_vault_id: VaultId,
        pub seed_record_id: RecordId,
        pub key_vault_id: VaultId,
        pub key_record_id: RecordId,
        pub hint: RecordHint,
    }

    impl Message for SLIP10DeriveFromSeed {
        type Result = Result<crate::ProcResult, anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct SLIP10DeriveFromKey {
        pub chain: Chain,
        pub parent_vault_id: VaultId,
        pub parent_record_id: RecordId,
        pub child_vault_id: VaultId,
        pub child_record_id: RecordId,
        pub hint: RecordHint,
    }

    impl Message for SLIP10DeriveFromKey {
        type Result = Result<crate::ProcResult, anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct BIP39Generate {
        pub passphrase: String,
        pub vault_id: VaultId,
        pub record_id: RecordId,
        pub hint: RecordHint,
    }

    impl Message for BIP39Generate {
        type Result = Result<crate::ProcResult, anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct BIP39Recover {
        pub mnemonic: String,
        pub passphrase: String,
        pub vault_id: VaultId,
        pub record_id: RecordId,
        pub hint: RecordHint,
    }

    impl Message for BIP39Recover {
        type Result = Result<crate::ProcResult, anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct Ed25519PublicKey {
        pub vault_id: VaultId,
        pub record_id: RecordId,
    }

    impl Message for Ed25519PublicKey {
        type Result = Result<crate::ProcResult, anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct Ed25519Sign {
        pub vault_id: VaultId,
        pub record_id: RecordId,
        pub msg: Vec<u8>,
    }

    impl Message for Ed25519Sign {
        type Result = Result<crate::ProcResult, anyhow::Error>;
    }

    #[derive(GuardDebug, Clone, Serialize, Deserialize)]
    pub enum SLIP10DeriveInput {
        /// Note that BIP39 seeds are allowed to be used as SLIP10 seeds
        Seed(Location),
        Key(Location),
    }

    #[derive(Clone, GuardDebug)]
    pub struct Sr25519Derive {
        pub chain: Vec<Sr25519DeriveJunction>,
        pub seed_vault_id: VaultId,
        pub seed_record_id: RecordId,
        pub key_vault_id: VaultId,
        pub key_record_id: RecordId,
        pub hint: RecordHint,
    }

    impl Message for Sr25519Derive {
        type Result = Result<crate::ProcResult, anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct Sr25519Generate {
        pub mnemonic_or_seed: Option<String>,
        pub passphrase: String,
        pub vault_id: VaultId,
        pub record_id: RecordId,
        pub hint: RecordHint,
    }

    impl Message for Sr25519Generate {
        type Result = Result<crate::ProcResult, anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct Sr25519PublicKey {
        pub vault_id: VaultId,
        pub record_id: RecordId,
    }

    impl Message for Sr25519PublicKey {
        type Result = Result<crate::ProcResult, anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct Sr25519Sign {
        pub vault_id: VaultId,
        pub record_id: RecordId,
        pub msg: Vec<u8>,
    }

    impl Message for Sr25519Sign {
        type Result = Result<crate::ProcResult, anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct Secp256k1Generate {
        pub vault_id: VaultId,
        pub record_id: RecordId,
        pub hint: RecordHint,
    }

    impl Message for Secp256k1Generate {
        type Result = Result<crate::ProcResult, anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct Secp256k1Store {
        pub key: Vec<u8>,
        pub vault_id: VaultId,
        pub record_id: RecordId,
        pub hint: RecordHint,
    }

    impl Message for Secp256k1Store {
        type Result = Result<crate::ProcResult, anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct Secp256k1PublicKey {
        pub vault_id: VaultId,
        pub record_id: RecordId,
    }

    impl Message for Secp256k1PublicKey {
        type Result = Result<crate::ProcResult, anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct Secp256k1Sign {
        pub vault_id: VaultId,
        pub record_id: RecordId,
        pub msg: Box<[u8; 32]>,
    }

    impl Message for Secp256k1Sign {
        type Result = Result<crate::ProcResult, anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct Web3SignTransaction<T: web3::Transport> {
        pub vault_id: VaultId,
        pub record_id: RecordId,
        pub accounts: Accounts<T>,
        pub tx: TransactionParameters,
    }

    impl<T: web3::Transport> Message for Web3SignTransaction<T> {
        type Result = Result<crate::ProcResult, anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct Web3Address<T: web3::Transport> {
        pub vault_id: VaultId,
        pub record_id: RecordId,
        pub accounts: Accounts<T>,
    }

    impl<T: web3::Transport> Message for Web3Address<T> {
        type Result = Result<crate::ProcResult, anyhow::Error>;
    }
}

/// Functional macro to remove boilerplate code for the implementation
/// of the [`SecureActor`].
/// TODO Make receiver type pass as argument.
macro_rules! impl_handler {
    ($mty:ty, $rty:ty, ($sid:ident,$mid:ident, $ctx:ident), $($body:tt)*) => {
        impl Handler<$mty> for SecureClient
        {
            type Result = $rty;
            fn handle(&mut $sid, $mid: $mty, $ctx: &mut Self::Context) -> Self::Result {
                $($body)*
            }
        }
    };

    ($mty:ty, $rty:ty, $($body:tt)*) => {
        impl_handler!($mty, $rty, (self,msg,ctx), $($body)*);
    }
}

#[cfg(test)]
pub mod testing {

    use super::*;
    use crate::Location;
    use serde::{Deserialize, Serialize};

    /// INSECURE MESSAGE
    /// MAY ONLY BE USED IN TESTING CONFIGURATIONS
    ///
    /// Reads data from the vault
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ReadFromVault {
        pub location: Location,
    }

    impl Message for ReadFromVault {
        type Result = Result<Vec<u8>, anyhow::Error>;
    }

    impl_handler!(ReadFromVault, Result<Vec<u8>, anyhow::Error>, (self, msg, _ctx), {
        let (vid, rid) = self.resolve_location(msg.location);

        let key = self.keystore.take_key(vid)?;

        let mut data = Vec::new();
        let res = self.db.get_guard(&key, vid, rid, |guarded_data| {
            let guarded_data = guarded_data.borrow();
            data.extend_from_slice(&*guarded_data);
            Ok(())
        });
        self.keystore.insert_key(vid, key);

        match res {
            Ok(_) => Ok(data),
            Err(e) => Err(anyhow::anyhow!(e)),
        }
    });
}

impl Actor for SecureClient {
    type Context = Context<Self>;
}

impl Supervised for SecureClient {}

impl_handler!(messages::Terminate, (), (self, _msg, ctx), {
    ctx.stop();
});

impl_handler!(messages::ClearCache, Result<(), anyhow::Error>, (self, _msg, _ctx), {
    self.keystore.clear_keys();
    self.db.clear().map_err(|e| anyhow::anyhow!(e))
});

impl_handler!(messages::CreateVault, (), (self, msg, _ctx), {
    let (vault_id, _) = self.resolve_location(msg.location);

    let key = self.keystore.create_key(vault_id);
    self.db.init_vault(key, vault_id).unwrap(); // potentially produces an error
});

impl_handler!(messages::CheckRecord, bool, (self, msg, _ctx), {
    let (vault_id, record_id) = self.resolve_location(msg.location);

    return match self.keystore.take_key(vault_id) {
        Ok(key) => {
            let res = self.db.contains_record(&key, vault_id, record_id);
            self.keystore.insert_key(vault_id, key);
            res
        }
        Err(_) => false,
    };
});

impl_handler!(messages::WriteToVault, Result<(), anyhow::Error>, (self, msg, _ctx), {
    let (vault_id, record_id) = self.resolve_location(msg.location);

    let key = self
        .keystore
        .take_key(vault_id)?;

    let res = self.db.write(&key, vault_id, record_id, &msg.payload, msg.hint);
    self.keystore.insert_key(vault_id, key);
    res.map_err(|e| anyhow::anyhow!(e))
});

impl_handler!(messages::RevokeData, Result<(), anyhow::Error>, (self, msg, _ctx), {
    let (vault_id, record_id) = self.resolve_location(msg.location);

    let key = self
        .keystore
        .take_key(vault_id)?;

    let res = self.db.revoke_record(&key, vault_id, record_id);
    self.keystore.insert_key(vault_id, key);
    res.map_err(|_| anyhow::anyhow!(VaultError::RevocationError))
});

impl_handler!(messages::GarbageCollect, Result<(), anyhow::Error>, (self, msg, _ctx), {
    let (vault_id, _) = self.resolve_location(msg.location);

    let key = self
        .keystore
        .take_key(vault_id)?;

    let res = self.db.garbage_collect_vault(&key, vault_id);
    self.keystore.insert_key(vault_id, key);
    res.map_err(|_| anyhow::anyhow!(VaultError::GarbageCollectError))
});

impl_handler!(
    messages::ListIds,
    Result<Vec<(RecordId, RecordHint)>, anyhow::Error>,
    (self, msg, _ctx),
    {
        let vault_id = self.derive_vault_id(msg.vault_path);
        let key = self.keystore.take_key(vault_id)?;

        let list = self.db.list_hints_and_ids(&key, vault_id);
        self.keystore.insert_key(vault_id, key);
        Ok(list)
    }
);

impl_handler!(messages::ReloadData, (), (self, msg, _ctx), {
    let (keystore, state, store) = *msg.data;
    self.keystore.rebuild_keystore(keystore);
    self.db = state;
    self.rebuild_cache(self.client_id, store);
});

impl_handler!(messages::CheckVault, bool, (self, msg, _ctx), {
    let vid = self.derive_vault_id(msg.vault_path);
    self.keystore.vault_exists(vid)
});

impl_handler!(messages::WriteToStore, Result<(), anyhow::Error>, (self, msg, _ctx), {
    let (vault_id, _) = self.resolve_location(msg.location);
    self.write_to_store(vault_id.into(), msg.payload, msg.lifetime);

    Ok(())
});

impl_handler!(
    messages::ReadFromStore,
    Result<Vec<u8>, anyhow::Error>,
    (self, msg, _ctx),
    {
        let (vault_id, _) = self.resolve_location(msg.location);

        match self.read_from_store(vault_id.into()) {
            Some(data) => Ok(data),
            None => Err(anyhow::anyhow!(StoreError::NotExisting)),
        }
    }
);

impl_handler!( messages::DeleteFromStore, Result <(), anyhow::Error>, (self, msg, _ctx), {
    let (vault_id, _) = self.resolve_location(msg.location);
    self.store_delete_item(vault_id.into());

    Ok(())
});

impl_handler!(
    messages::GetData,
    Result<
        Box<(
            HashMap<VaultId, Key<internals::Provider>>,
            DbView<internals::Provider>,
            Store
        )>,
        anyhow::Error,
    >,
    (self, _msg, _ctx),
    {
        let keystore = self.keystore.get_data();
        let dbview = self.db.clone();
        let store = self.store.clone();

        Ok(Box::from((keystore, dbview, store)))
    }
);

// ----
// impl for procedures
// ---

/// Intermediate handler for executing procedures
/// will be replace by upcoming `procedures api`
impl<T: web3::Transport + Send + Sync> Handler<CallProcedure<T>> for SecureClient {
    type Result = Result<procedures::ProcResult, anyhow::Error>;

    fn handle(&mut self, msg: CallProcedure<T>, ctx: &mut Self::Context) -> Self::Result {
        // // TODO move
        use procedures::*;

        // // shifted from interface, that passes the procedure to here
        let procedure = msg.proc;
        match procedure {
            Procedure::SLIP10Generate {
                output,
                hint,
                size_bytes,
            } => {
                let (vault_id, record_id) = self.resolve_location(output);

                <Self as Handler<SLIP10Generate>>::handle(
                    self,
                    SLIP10Generate {
                        vault_id,
                        record_id,
                        hint,
                        size_bytes: size_bytes.unwrap_or(64),
                    },
                    ctx,
                )
            }
            Procedure::SLIP10Derive {
                chain,
                input,
                output,
                hint,
            } => match input {
                SLIP10DeriveInput::Key(parent) => {
                    let (parent_vault_id, parent_record_id) = self.resolve_location(parent);

                    let (child_vault_id, child_record_id) = self.resolve_location(output);

                    <Self as Handler<SLIP10DeriveFromKey>>::handle(
                        self,
                        SLIP10DeriveFromKey {
                            chain,
                            hint,
                            parent_vault_id,
                            parent_record_id,
                            child_vault_id,
                            child_record_id,
                        },
                        ctx,
                    )
                }
                SLIP10DeriveInput::Seed(seed) => {
                    let (seed_vault_id, seed_record_id) = self.resolve_location(seed);

                    let (key_vault_id, key_record_id) = self.resolve_location(output);

                    <Self as Handler<SLIP10DeriveFromSeed>>::handle(
                        self,
                        SLIP10DeriveFromSeed {
                            chain,
                            hint,
                            seed_vault_id,
                            seed_record_id,
                            key_vault_id,
                            key_record_id,
                        },
                        ctx,
                    )
                }
            },

            Procedure::BIP39Recover {
                mnemonic,
                passphrase,
                output,
                hint,
            } => {
                let (vault_id, record_id) = self.resolve_location(output);

                <Self as Handler<BIP39Recover>>::handle(
                    self,
                    BIP39Recover {
                        mnemonic,
                        passphrase: passphrase.unwrap_or_else(|| "".into()),
                        vault_id,
                        record_id,
                        hint,
                    },
                    ctx,
                )
            }

            Procedure::BIP39Generate {
                passphrase,
                output,
                hint,
            } => {
                let (vault_id, record_id) = self.resolve_location(output);

                <Self as Handler<BIP39Generate>>::handle(
                    self,
                    BIP39Generate {
                        passphrase: passphrase.unwrap_or_else(|| "".into()),
                        vault_id,
                        record_id,
                        hint,
                    },
                    ctx,
                )
            }

            Procedure::BIP39MnemonicSentence { seed: _ } => {
                unimplemented!()
            }

            Procedure::Ed25519PublicKey { private_key } => {
                let (vault_id, record_id) = self.resolve_location(private_key);

                <Self as Handler<Ed25519PublicKey>>::handle(self, Ed25519PublicKey { vault_id, record_id }, ctx)
            }
            Procedure::Ed25519Sign { private_key, msg } => {
                let (vault_id, record_id) = self.resolve_location(private_key);

                <Self as Handler<Ed25519Sign>>::handle(
                    self,
                    Ed25519Sign {
                        vault_id,
                        record_id,
                        msg,
                    },
                    ctx,
                )
            }
            // sr25519 procedures
            Procedure::Sr25519Derive {
                chain,
                input,
                output,
                hint,
            } => {
                let (seed_vault_id, seed_record_id) = self.resolve_location(input);
                let (key_vault_id, key_record_id) = self.resolve_location(output);
                <Self as Handler<Sr25519Derive>>::handle(
                    self,
                    Sr25519Derive {
                        chain,
                        seed_vault_id,
                        seed_record_id,
                        key_vault_id,
                        key_record_id,
                        hint,
                    },
                    ctx,
                )
            }
            Procedure::Sr25519Generate {
                mnemonic_or_seed,
                passphrase,
                output,
                hint,
            } => {
                let (vault_id, record_id) = self.resolve_location(output);
                <Self as Handler<Sr25519Generate>>::handle(
                    self,
                    Sr25519Generate {
                        mnemonic_or_seed,
                        passphrase: passphrase.unwrap_or_else(|| "".into()),
                        vault_id,
                        record_id,
                        hint,
                    },
                    ctx,
                )
            }
            Procedure::Sr25519PublicKey { keypair } => {
                let (vault_id, record_id) = self.resolve_location(keypair);
                <Self as Handler<Sr25519PublicKey>>::handle(self, Sr25519PublicKey { vault_id, record_id }, ctx)
            }
            Procedure::Sr25519Sign { keypair, msg } => {
                let (vault_id, record_id) = self.resolve_location(keypair);
                <Self as Handler<Sr25519Sign>>::handle(
                    self,
                    Sr25519Sign {
                        vault_id,
                        record_id,
                        msg,
                    },
                    ctx,
                )
            }
            // secp256k1
            Procedure::Secp256k1Generate { output, hint } => {
                let (vault_id, record_id) = self.resolve_location(output);
                <Self as Handler<Secp256k1Generate>>::handle(
                    self,
                    Secp256k1Generate {
                        vault_id,
                        record_id,
                        hint,
                    },
                    ctx,
                )
            }
            Procedure::Secp256k1Store { key, output, hint } => {
                let (vault_id, record_id) = self.resolve_location(output);
                <Self as Handler<Secp256k1Store>>::handle(
                    self,
                    Secp256k1Store {
                        key,
                        vault_id,
                        record_id,
                        hint,
                    },
                    ctx,
                )
            }
            Procedure::Secp256k1PublicKey { private_key } => {
                let (vault_id, record_id) = self.resolve_location(private_key);
                <Self as Handler<Secp256k1PublicKey>>::handle(self, Secp256k1PublicKey { vault_id, record_id }, ctx)
            }
            Procedure::Secp256k1Sign { private_key, msg } => {
                let (vault_id, record_id) = self.resolve_location(private_key);
                <Self as Handler<Secp256k1Sign>>::handle(
                    self,
                    Secp256k1Sign {
                        vault_id,
                        record_id,
                        msg,
                    },
                    ctx,
                )
            }
            // web3
            Procedure::Web3SignTransaction {
                accounts,
                tx,
                private_key,
            } => {
                let (vault_id, record_id) = self.resolve_location(private_key);
                <Self as Handler<Web3SignTransaction<T>>>::handle(
                    self,
                    Web3SignTransaction {
                        vault_id,
                        record_id,
                        accounts,
                        tx,
                    },
                    ctx,
                )
            }
            Procedure::Web3Address { accounts, private_key } => {
                let (vault_id, record_id) = self.resolve_location(private_key);
                <Self as Handler<Web3Address<T>>>::handle(
                    self,
                    Web3Address {
                        vault_id,
                        record_id,
                        accounts,
                    },
                    ctx,
                )
            }
        }
    }
}

impl_handler!(procedures::SLIP10Generate, Result<crate::ProcResult, anyhow::Error>, (self, msg, _ctx), {
    if !self.keystore.vault_exists(msg.vault_id) {
        let key = self.keystore.create_key(msg.vault_id);
        self.db.init_vault(key, msg.vault_id)?;
    }
    let key = self.keystore.take_key(msg.vault_id).unwrap();

    let mut seed = vec![0u8; msg.size_bytes];
    match fill(&mut seed) {
        Ok(_) => {},
        Err(e) => {
            self.keystore.insert_key(msg.vault_id, key);
            return Err(anyhow::anyhow!(e))
        }
    }

    let res = self.db.write(&key, msg.vault_id, msg.record_id, &seed, msg.hint);

    self.keystore.insert_key(msg.vault_id, key);

    match res {
        Ok(_) => Ok(ProcResult::SLIP10Generate(StatusMessage::OK)),
        Err(e) => Err(anyhow::anyhow!(e)),
    }
});

impl_handler!(procedures::SLIP10DeriveFromSeed, Result<crate::ProcResult, anyhow::Error>, (self, msg, _ctx), {
    let seed_key = self
        .keystore
        .take_key(msg.seed_vault_id)?;

    if !self.keystore.vault_exists(msg.key_vault_id) {
        let key = self.keystore.create_key(msg.key_vault_id);
        match self.db.init_vault(key, msg.key_vault_id) {
            Ok(_) => {},
            Err(e) => {
                self.keystore.insert_key(msg.seed_vault_id, seed_key);
                return Err(anyhow::anyhow!(e))
            }
        }
    }
    let dk_key = self.keystore.take_key(msg.key_vault_id).unwrap();

    // FIXME if you see this fix here, that a single-threaded mutable reference
    // is being passed into the closure to obtain the result of the pro-
    // cedure calculation, you should consider rethinking this approach.

    let result = Rc::new(Cell::default());

    let res = self.db.exec_proc(
        &seed_key,
        msg.seed_vault_id,
        msg.seed_record_id,
        &dk_key,
        msg.key_vault_id,
        msg.key_record_id,
        msg.hint,
        |gdata| {
            let dk = Seed::from_bytes(&gdata.borrow())
                .derive(Curve::Ed25519, &msg.chain)
                .map_err(|e| anyhow::anyhow!(e))
                .unwrap();
            let data: Vec<u8> = dk.into();

            result.set(dk.chain_code());

            Ok(data)
        },
    );

    self.keystore.insert_key(msg.seed_vault_id, seed_key);
    self.keystore.insert_key(msg.key_vault_id, dk_key);

    match res {
        Ok(_) => Ok(ProcResult::SLIP10Derive(ResultMessage::Ok(result.get()))),
        Err(e) => Err(anyhow::anyhow!(e)),
    }
});

impl_handler!( procedures::SLIP10DeriveFromKey,Result<crate::ProcResult, anyhow::Error>, (self, msg, _ctx),{
    let parent_key = self
        .keystore
        .take_key(msg.parent_vault_id)?;

    if !self.keystore.vault_exists(msg.child_vault_id) {
        let key = self.keystore.create_key(msg.child_vault_id);
        match self.db.init_vault(key, msg.child_vault_id) {
            Ok(_) => {},
            Err(e) => {
                self.keystore.insert_key(msg.parent_vault_id, parent_key);
                return Err(anyhow::anyhow!(e))
            }
        }
    }
    let child_key = self.keystore.take_key(msg.child_vault_id).unwrap();

    let result = Rc::new(Cell::default());

    let res = self.db.exec_proc(
        &parent_key,
        msg.parent_vault_id,
        msg.parent_record_id,
        &child_key,
        msg.child_vault_id,
        msg.child_record_id,
        msg.hint,
        |parent| {
            let parent = slip10::Key::try_from(&*parent.borrow()).unwrap();
            let dk = parent.derive(&msg.chain).unwrap();

            let data: Vec<u8> = dk.into();

            result.set(dk.chain_code());

            Ok(data)
        },
    );

    self.keystore.insert_key(msg.parent_vault_id, parent_key);
    self.keystore.insert_key(msg.child_vault_id, child_key);

    match res {
        Ok(_) => Ok(ProcResult::SLIP10Derive(ResultMessage::Ok(result.get()))),
        Err(e) => Err(anyhow::anyhow!(e)),
    }
});

impl_handler!(procedures::BIP39Generate, Result<crate::ProcResult, anyhow::Error>, (self, msg, _ctx), {
    let mut entropy = [0u8; 32];
    fill(&mut entropy).map_err(|e| anyhow::anyhow!(e))?;
    let mnemonic = bip39::wordlist::encode(
        &entropy,
        &bip39::wordlist::ENGLISH, // TODO: make this user configurable
    ).map_err(|e| anyhow::anyhow!(format!("{:?}", e)))?;

    let mut seed = [0u8; 64];
    bip39::mnemonic_to_seed(&mnemonic, &msg.passphrase, &mut seed);

    if !self.keystore.vault_exists(msg.vault_id) {
        let key = self.keystore.create_key(msg.vault_id);
        self.db.init_vault(key, msg.vault_id)?;
    }
    let key = self.keystore.take_key(msg.vault_id).unwrap();

    let res = self.db.write(&key, msg.vault_id, msg.record_id, &seed, msg.hint);

    self.keystore.insert_key(msg.vault_id, key);

    // TODO: also store the mnemonic to be able to export it in the
    // BIP39MnemonicSentence message
    match res {
        Ok(_) => Ok(ProcResult::BIP39Generate(ResultMessage::OK)),
        Err(e) => Err(anyhow::anyhow!(e)),
    }
});

impl_handler!(procedures::BIP39Recover, Result<crate::ProcResult, anyhow::Error>, (self, msg, _ctx), {
    if !self.keystore.vault_exists(msg.vault_id) {
        let key = self.keystore.create_key(msg.vault_id);
        self.db.init_vault(key, msg.vault_id)?;
    }
    let key = self.keystore.take_key(msg.vault_id).unwrap();

    let mut seed = [0u8; 64];
    bip39::mnemonic_to_seed(&msg.mnemonic, &msg.passphrase, &mut seed);

    let res = self.db.write(&key, msg.vault_id, msg.record_id, &seed, msg.hint);
    self.keystore.insert_key(msg.vault_id, key);

    // TODO: also store the mnemonic to be able to export it in the
    // BIP39MnemonicSentence message
    match res {
        Ok(_) => Ok(ProcResult::BIP39Recover(ResultMessage::OK)),
        Err(e) => Err(anyhow::anyhow!(e)),
    }
});

impl_handler!(procedures::Ed25519PublicKey, Result<crate::ProcResult, anyhow::Error>, (self, msg, _ctx), {
    let key = self
        .keystore
        .take_key(msg.vault_id)?;

    let result = Rc::new(Cell::default());

    let res = self.db.get_guard(&key, msg.vault_id, msg.record_id, |data| {
        let raw = data.borrow();
        let mut raw = (*raw).to_vec();

        if raw.len() < 32 {
            return Err(engine::Error::CryptoError(crypto::error::Error::BufferSize {
                has: raw.len(),
                needs: 32,
                name: "data buffer",
            }));
        }
        raw.truncate(32);
        let mut bs = [0; 32];
        bs.copy_from_slice(&raw);

        let sk = ed25519::SecretKey::from_bytes(bs);
        let pk = sk.public_key();

        // send to client this result
        result.set(pk.to_bytes());

        Ok(())
    });
    self.keystore.insert_key(msg.vault_id, key);

    match res {
        Ok(_) => Ok(ProcResult::Ed25519PublicKey(ResultMessage::Ok(result.get()))),
        Err(e) => Err(anyhow::anyhow!(e)),
    }
});

impl_handler!(procedures::Ed25519Sign, Result <crate::ProcResult, anyhow::Error>, (self, msg, _ctx), {
    let pkey = self
        .keystore
        .take_key(msg.vault_id)?;

    let result = Rc::new(Cell::new([0u8; 64]));

    let res = self.db.get_guard(&pkey, msg.vault_id, msg.record_id, |data| {
        let raw = data.borrow();
        let mut raw = (*raw).to_vec();

        if raw.len() < 32 {
            return Err(engine::Error::CryptoError(crypto::Error::BufferSize {
                has: raw.len(),
                needs: 32,
                name: "data buffer",
            }));
        }
        raw.truncate(32);
        let mut bs = [0; 32];
        bs.copy_from_slice(&raw);

        let sk = ed25519::SecretKey::from_bytes(bs);

        let sig = sk.sign(&msg.msg);
        result.set(sig.to_bytes());

        Ok(())
    });

    self.keystore.insert_key(msg.vault_id, pkey);

    match res {
        Ok(_) => Ok(ProcResult::Ed25519Sign(ResultMessage::Ok(result.get()))),
        Err(e) => Err(anyhow::anyhow!(e)),
    }

});

impl_handler!(procedures::Sr25519Derive, Result<crate::ProcResult, anyhow::Error>, (self, msg, _ctx), {
    match self.keystore.take_key(msg.seed_vault_id) {
        Ok(seed_key) => {
            self.keystore.insert_key(msg.seed_vault_id, seed_key.clone());
            if !self.keystore.vault_exists(msg.key_vault_id) {
                let key = self.keystore.create_key(msg.key_vault_id);
                self.db.init_vault(key, msg.key_vault_id)?;
            }
            let dk_key = self.keystore.take_key(msg.key_vault_id).unwrap();
            self.keystore.insert_key(msg.key_vault_id, dk_key.clone());

            self.db
                .exec_proc(
                    &seed_key,
                    msg.seed_vault_id,
                    msg.seed_record_id,
                    &dk_key,
                    msg.key_vault_id,
                    msg.key_record_id,
                    msg.hint,
                    move |gdata| {
                        let dk = Sr25519KeyPair::from_seed(&gdata.borrow())
                            .derive(msg.chain.into_iter(), None)?;
                        let data = dk.seed().to_vec();
                        Ok(data)
                    },
                )
                .map_err(|e| anyhow::anyhow!(e))?;

            Ok(ProcResult::Sr25519Derive(StatusMessage::OK))
        }
        _ => Err(anyhow::anyhow!("Failed to access vault")),
    }
});

impl_handler!(procedures::Sr25519Generate, Result<crate::ProcResult, anyhow::Error>, (self, msg, _ctx), {
    let keypair = match msg.mnemonic_or_seed {
        Some(m) => Sr25519KeyPair::from_string(&m, Some(&msg.passphrase)),
        None => {
            let mut entropy = [0u8; 32];
            fill(&mut entropy).map_err(|e| anyhow::anyhow!(e))?;

            let mnemonic =
                bip39::wordlist::encode(&entropy, &bip39::wordlist::ENGLISH).map_err(|e| anyhow::anyhow!(format!("{:?}", e)))?;

            Sr25519KeyPair::from_string(&mnemonic, Some(&msg.passphrase))
        }
    };

    if !self.keystore.vault_exists(msg.vault_id) {
        let key = self.keystore.create_key(msg.vault_id);
        self.db.init_vault(key, msg.vault_id)?;
    }
    let key = self.keystore.take_key(msg.vault_id).unwrap();

    self.keystore.insert_key(msg.vault_id, key.clone());

    match keypair {
        Ok(keypair) => {
            self.db
                .write(&key, msg.vault_id, msg.record_id, &keypair.seed(), msg.hint)?;

            Ok(ProcResult::Sr25519Generate(StatusMessage::OK))
        }
        Err(e) => {
            Err(anyhow::anyhow!("failed to generate key pair: {}", e.to_string()))
        }
    }
});

impl_handler!(procedures::Sr25519PublicKey, Result<crate::ProcResult, anyhow::Error>, (self, msg, _ctx), {
    let key = self.keystore.take_key(msg.vault_id)?;
    self.keystore.insert_key(msg.vault_id, key.clone());

    let result = Rc::new(Cell::new(None));

    self.db
        .get_guard(&key, msg.vault_id, msg.record_id, |data| {
            let raw = data.borrow();

            if raw.len() != 64 {
                return Err(engine::Error::DatabaseError("incorrect number of private key bytes".into()));
            }

            let keypair = Sr25519KeyPair::from_seed(&raw);
            let pk = keypair.public_key();

            result.set(Some(pk));

            Ok(())
        })
        .map_err(|e| anyhow::anyhow!(e))?;

    Ok(ProcResult::Sr25519PublicKey(ResultMessage::Ok(result.take().unwrap())))
});

impl_handler!(procedures::Sr25519Sign, Result<crate::ProcResult, anyhow::Error>, (self, msg, _ctx), {
    let key = self.keystore.take_key(msg.vault_id)?;
    self.keystore.insert_key(msg.vault_id, key.clone());

    let result = Rc::new(Cell::new(None));

    self.db
        .get_guard(&key, msg.vault_id, msg.record_id, |data| {
            let raw = data.borrow();

            if raw.len() != 64 {
                return Err(engine::Error::DatabaseError("incorrect number of private key bytes".into()));
            }

            let keypair = Sr25519KeyPair::from_seed(&raw);
            let sig = keypair.sign(&msg.msg);

            result.set(Some(sig));

            Ok(())
        })
        .map_err(|e| anyhow::anyhow!(e))?;

    Ok(ProcResult::Sr25519Sign(ResultMessage::Ok(result.take().unwrap())))
});

impl_handler!(procedures::Secp256k1Generate, Result<crate::ProcResult, anyhow::Error>, (self, msg, _ctx), {
    let mut key = vec![0u8; SECP256K1_SECRET_KEY_LENGTH];
    fill(&mut key).map_err(|e| anyhow::anyhow!(e))?;
    let private_key = Secp256k1SecretKey::from_bytes(&key.try_into().unwrap()).map_err(|e| anyhow::anyhow!(e))?;

    if !self.keystore.vault_exists(msg.vault_id) {
        let key = self.keystore.create_key(msg.vault_id);
        self.db.init_vault(key, msg.vault_id)?;
    }
    let key = self.keystore.take_key(msg.vault_id).unwrap();

    self.keystore.insert_key(msg.vault_id, key.clone());

    self.db
        .write(&key, msg.vault_id, msg.record_id, &private_key.to_bytes(), msg.hint)?;

    Ok(ProcResult::Secp256k1Generate(StatusMessage::OK))
});

impl_handler!(procedures::Secp256k1Store, Result<crate::ProcResult, anyhow::Error>, (self, msg, _ctx), {
    if msg.key.len() != SECP256K1_SECRET_KEY_LENGTH {
        return Err(anyhow::anyhow!("incorrect number of private key bytes"));
    }
    let private_key = Secp256k1SecretKey::from_bytes(&msg.key.try_into().unwrap()).map_err(|e| anyhow::anyhow!(e))?;

    if !self.keystore.vault_exists(msg.vault_id) {
        let key = self.keystore.create_key(msg.vault_id);
        self.db.init_vault(key, msg.vault_id)?;
    }
    let key = self.keystore.take_key(msg.vault_id).unwrap();

    self.keystore.insert_key(msg.vault_id, key.clone());

    self.db
        .write(&key, msg.vault_id, msg.record_id, &private_key.to_bytes(), msg.hint)?;

    Ok(ProcResult::Secp256k1Generate(StatusMessage::OK))
});

impl_handler!(procedures::Secp256k1PublicKey, Result<crate::ProcResult, anyhow::Error>, (self, msg, _ctx), {
    let key = self.keystore.take_key(msg.vault_id)?;
    self.keystore.insert_key(msg.vault_id, key.clone());

    let result = Rc::new(Cell::new(None));

    self.db
        .get_guard(&key, msg.vault_id, msg.record_id, |data| {
            let raw = data.borrow();

            if raw.len() != SECP256K1_SECRET_KEY_LENGTH {
                return Err(engine::Error::DatabaseError("incorrect number of private key bytes".into()));
            }

            let private_key = Secp256k1SecretKey::from_bytes(&raw.deref().try_into()?)?;
            let pk = private_key.public_key();

            result.set(Some(pk));

            Ok(())
        })
        .map_err(|e| anyhow::anyhow!(e))?;

    Ok(ProcResult::Secp256k1PublicKey(ResultMessage::Ok(result.take().unwrap())))
});

impl_handler!(procedures::Secp256k1Sign, Result<crate::ProcResult, anyhow::Error>, (self, msg, _ctx), {
    let key = self.keystore.take_key(msg.vault_id)?;
    self.keystore.insert_key(msg.vault_id, key.clone());

    let result = Rc::new(Cell::new(None));

    self.db
        .get_guard(&key, msg.vault_id, msg.record_id, |data| {
            let raw = data.borrow();

            if raw.len() != SECP256K1_SECRET_KEY_LENGTH {
                return Err(engine::Error::DatabaseError("incorrect number of private key bytes".into()));
            }

            let private_key = Secp256k1SecretKey::from_bytes(&raw.deref().try_into()?)?;
            let (sig, recovery_id) = private_key.sign(&msg.msg);
            result.set(Some((sig, recovery_id)));

            Ok(())
        })
        .map_err(|e| anyhow::anyhow!(e))?;

    Ok(ProcResult::Secp256k1Sign(ResultMessage::Ok(result.take().unwrap())))
});

struct Secp256k1SecretKeyRef<'a>(&'a Secp256k1SecretKey);

// taken from https://github.com/tomusdrw/rust-web3/blob/2711cd00d51bbfa6be1996cebdd991f7ed77115c/src/signing.rs#L101
impl<'a> Web3Key for Secp256k1SecretKeyRef<'a> {
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

    fn address(&self) -> Web3AddressType {
        let public_key = self.0.public_key();
        let public_key = public_key.to_bytes();

        debug_assert_eq!(public_key[0], 0x04);
        let hash = keccak256(&public_key[1..]);

        Web3AddressType::from_slice(&hash[12..])
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

impl<T: web3::Transport> Handler<procedures::Web3SignTransaction<T>> for SecureClient {
    type Result = Result<crate::ProcResult, anyhow::Error>;
    fn handle(&mut self, msg: procedures::Web3SignTransaction<T>, _ctx: &mut Self::Context) -> Self::Result {
        let key = self.keystore.take_key(msg.vault_id)?;
        self.keystore.insert_key(msg.vault_id, key.clone());

        let result = Rc::new(Cell::new(None));

        self.db
            .get_guard(&key, msg.vault_id, msg.record_id, |data| {
                let raw = data.borrow();

                if raw.len() != SECP256K1_SECRET_KEY_LENGTH {
                    return Err(engine::Error::DatabaseError(
                        "incorrect number of private key bytes".into(),
                    ));
                }

                let private_key = Secp256k1SecretKey::from_bytes(&raw.deref().try_into()?)?;
                let key = Secp256k1SecretKeyRef(&private_key);

                match futures::executor::block_on(msg.accounts.sign_transaction(msg.tx, key)) {
                    Ok(signed_transaction) => {
                        result.set(Some(signed_transaction));
                        Ok(())
                    }
                    Err(e) => Err(engine::Error::DatabaseError(format!(
                        "failed to sign transaction: {}",
                        e.to_string()
                    ))),
                }
            })
            .map_err(|e| anyhow::anyhow!(e))?;

        Ok(ProcResult::Web3SignTransaction(ResultMessage::Ok(
            result.take().unwrap(),
        )))
    }
}

impl<T: web3::Transport> Handler<procedures::Web3Address<T>> for SecureClient {
    type Result = Result<crate::ProcResult, anyhow::Error>;
    fn handle(&mut self, msg: procedures::Web3Address<T>, _ctx: &mut Self::Context) -> Self::Result {
        let key = self.keystore.take_key(msg.vault_id)?;
        self.keystore.insert_key(msg.vault_id, key.clone());

        let result = Rc::new(Cell::new(None));

        self.db
            .get_guard(&key, msg.vault_id, msg.record_id, |data| {
                let raw = data.borrow();

                if raw.len() != 32 {
                    return Err(engine::Error::DatabaseError(format!(
                        "incorrect number of private key bytes, expected 32 but found {}",
                        raw.len()
                    )));
                }

                let private_key = Secp256k1SecretKey::from_bytes(&raw.deref().try_into()?)?;
                let key = Secp256k1SecretKeyRef(&private_key);
                result.set(Some(key.address()));
                Ok(())
            })
            .map_err(|e| anyhow::anyhow!(e))?;

        Ok(ProcResult::Web3Address(ResultMessage::Ok(result.take().unwrap())))
    }
}
