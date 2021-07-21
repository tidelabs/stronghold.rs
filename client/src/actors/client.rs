// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    actors::{InternalMsg, InternalResults, SMsg},
    line_error,
    state::client::{Client, ClientMsg},
    utils::{ResultMessage, StatusMessage},
    Location,
};

use stronghold_utils::GuardDebug;

use crypto::{
    keys::slip10::{Chain, ChainCode},
    signatures::{
        secp256k1::{
            PublicKey as Secp256k1PublicKey, RecoveryId as Secp256k1RecoveryId, Signature as Secp256k1Signature,
            PUBLIC_KEY_LENGTH as SECP256K1_PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH as SECP256K1_SIGNATURE_LENGTH,
        },
        sr25519::{
            PublicKey as Sr25519PublicKey, Signature as Sr25519Signature,
            PUBLIC_KEY_LENGTH as SR25519_PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH as SR25519_SIGNATURE_LENGTH,
        },
    },
};

use engine::{
    snapshot,
    vault::{ClientId, RecordHint, RecordId},
};
use serde::{Deserialize, Serialize};

use riker::actors::*;

use core::{
    array::TryFromSliceError,
    convert::{TryFrom, TryInto},
};
use std::{path::PathBuf, time::Duration};

#[cfg(feature = "communication")]
use communication::actor::{PermissionValue, RequestPermissions, ToPermissionVariants, VariantPermission};

/// `SLIP10DeriveInput` type used to specify a Seed location or a Key location for the `SLIP10Derive` procedure.
#[derive(GuardDebug, Clone, Serialize, Deserialize)]
pub enum SLIP10DeriveInput {
    /// Note that BIP39 seeds are allowed to be used as SLIP10 seeds
    Seed(Location),
    Key(Location),
}

/// Procedure type used to call to the runtime via `Strongnhold.runtime_exec(...)`.
#[allow(dead_code)]
#[derive(GuardDebug, Clone, Serialize, Deserialize)]
pub enum Procedure {
    /// Generate a raw SLIP10 seed of the specified size (in bytes, defaults to 64 bytes/512 bits) and store it in the
    /// `output` location
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
    /// Gets the public key associated with the secp256k1 secret key stored on the given location.
    Secp256k1PublicKey { private_key: Location },
    /// Use the specified secp256k1 secret key to sign the given message.
    Secp256k1Sign { private_key: Location, msg: Box<[u8; 32]> },
}

/// A Procedure return result type.  Contains the different return values for the `Procedure` type calls used with
/// `Stronghold.runtime_exec(...)`.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    Ed25519PublicKey(ResultMessage<[u8; crypto::signatures::ed25519::COMPRESSED_PUBLIC_KEY_LENGTH]>),
    /// Return value for `Ed25519Sign`. Returns an Ed25519 signature.
    Ed25519Sign(ResultMessage<[u8; crypto::signatures::ed25519::SIGNATURE_LENGTH]>),
    /// Returns the public key derived from the `Sr25519Derive` call.
    Sr25519Derive(StatusMessage),
    /// `Sr25519Generate` return value.
    Sr25519Generate(StatusMessage),
    /// Return value for `Sr25519PublicKey`. Returns an sr25519 public key.
    Sr25519PublicKey(ResultMessage<Sr25519PublicKey>),
    /// Return value for `Sr25519Sign`. Returns an sr25519 signature.
    Sr25519Sign(ResultMessage<Sr25519Signature>),
    /// `Secp256k1Generate` return value.
    Secp256k1Generate(StatusMessage),
    /// Return value for `Secp256k1PublicKey`. Returns a secp256k1 public key.
    Secp256k1PublicKey(ResultMessage<Secp256k1PublicKey>),
    /// Return value for `Secp256k1Sign`. Returns a secp256k1 signature.
    Secp256k1Sign(ResultMessage<(Secp256k1Signature, Secp256k1RecoveryId)>),
    /// Generic Error return message.
    Error(String),
}

impl TryFrom<SerdeProcResult> for ProcResult {
    type Error = TryFromSliceError;

    fn try_from(serde_proc_result: SerdeProcResult) -> Result<Self, TryFromSliceError> {
        match serde_proc_result {
            SerdeProcResult::SLIP10Generate(msg) => Ok(ProcResult::SLIP10Generate(msg)),
            SerdeProcResult::SLIP10Derive(msg) => Ok(ProcResult::SLIP10Derive(msg)),
            SerdeProcResult::BIP39Recover(msg) => Ok(ProcResult::BIP39Recover(msg)),
            SerdeProcResult::BIP39Generate(msg) => Ok(ProcResult::BIP39Generate(msg)),
            SerdeProcResult::BIP39MnemonicSentence(msg) => Ok(ProcResult::BIP39MnemonicSentence(msg)),
            SerdeProcResult::Ed25519PublicKey(msg) => {
                let msg: ResultMessage<[u8; crypto::signatures::ed25519::COMPRESSED_PUBLIC_KEY_LENGTH]> = match msg {
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
                let msg: ResultMessage<Sr25519PublicKey> = match msg {
                    ResultMessage::Ok(v) => ResultMessage::Ok(Sr25519PublicKey::from_raw(v.as_slice().try_into()?)),
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
            SerdeProcResult::Secp256k1PublicKey(msg) => {
                let msg: ResultMessage<Secp256k1PublicKey> = match msg {
                    ResultMessage::Ok(v) => ResultMessage::Ok(
                        Secp256k1PublicKey::from_bytes(v.as_slice().try_into()?).expect(line_error!()),
                    ),
                    ResultMessage::Error(e) => ResultMessage::Error(e),
                };
                Ok(ProcResult::Secp256k1PublicKey(msg))
            }
            SerdeProcResult::Secp256k1Sign(r) => {
                let msg: ResultMessage<(Secp256k1Signature, Secp256k1RecoveryId)> = match r {
                    ResultMessage::Ok((sig, recovery_id)) => ResultMessage::Ok((
                        Secp256k1Signature::from_bytes(sig.as_slice().try_into()?).expect(line_error!()),
                        Secp256k1RecoveryId::from_u8(recovery_id).expect(line_error!()),
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
            ProcResult::Error(err) => SerdeProcResult::Error(err),
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, GuardDebug, Serialize, Deserialize)]
#[cfg_attr(feature = "communication", derive(RequestPermissions))]
pub enum SHRequest {
    // check if vault exists.
    CheckVault(Vec<u8>),
    // check if record exists.
    CheckRecord {
        location: Location,
    },
    // Write to the store.
    WriteToStore {
        location: Location,
        payload: Vec<u8>,
        lifetime: Option<Duration>,
    },
    // Read from the store.
    ReadFromStore {
        location: Location,
    },
    // Delete a key/value pair from the store.
    DeleteFromStore(Location),

    // Creates a new Vault.
    CreateNewVault(Location),

    // Write to the Vault.
    WriteToVault {
        location: Location,
        payload: Vec<u8>,
        hint: RecordHint,
    },

    // Reads data from a record in the vault. Accepts a vault id and an optional record id. Returns with `ReturnRead`.
    #[cfg(test)]
    ReadFromVault {
        location: Location,
    },
    // Marks a Record for deletion.  Accepts a vault id and a record id.  Deletion only occurs after a
    // `GarbageCollect` is called.
    RevokeData {
        location: Location,
    },
    // Garbages collects any marked records on a Vault. Accepts the vault id.
    GarbageCollect(Vec<u8>),
    // Lists all of the record ids and the record hints for the records in a vault.  Accepts a vault id and returns
    // with `ReturnList`.
    ListIds(Vec<u8>),

    // Reads from the snapshot file.  Accepts the snapshot key, an optional filename and an optional filepath.
    // Defaults to `$HOME/.engine/snapshots/backup.snapshot`.
    ReadSnapshot {
        key: snapshot::Key,
        filename: Option<String>,
        path: Option<PathBuf>,
        cid: ClientId,
        former_cid: Option<ClientId>,
    },
    // Writes to the snapshot file. Accepts the snapshot key, an optional filename and an optional filepath.
    // Defaults to `$HOME/.engine/snapshots/backup.snapshot`.
    WriteSnapshot {
        key: snapshot::Key,
        filename: Option<String>,
        path: Option<PathBuf>,
    },
    // Helper to fill the snapshot state before the write operation.
    FillSnapshot,

    // Clear the cache of the bucket.
    ClearCache {
        kill: bool,
    },

    // Interact with the runtime.
    ControlRequest(Procedure),
}

/// Return messages that come from stronghold
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SHResults {
    ReturnWriteStore(StatusMessage),
    ReturnReadStore(Vec<u8>, StatusMessage),
    ReturnDeleteStore(StatusMessage),
    ReturnCreateVault(StatusMessage),
    ReturnWriteVault(StatusMessage),
    ReturnReadVault(Vec<u8>, StatusMessage),
    ReturnRevoke(StatusMessage),
    ReturnGarbage(StatusMessage),
    ReturnList(Vec<(RecordId, RecordHint)>, StatusMessage),
    ReturnFillSnap(StatusMessage),
    ReturnWriteSnap(StatusMessage),
    ReturnReadSnap(StatusMessage),
    ReturnClearCache(StatusMessage),
    ReturnControlRequest(ProcResult),
    ReturnExistsVault(bool),
    ReturnExistsRecord(bool),
}

impl ActorFactoryArgs<ClientId> for Client {
    fn create_args(client_id: ClientId) -> Self {
        Client::new(client_id)
    }
}

/// Actor implementation for the Client.
impl Actor for Client {
    type Msg = ClientMsg;

    fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        self.receive(ctx, msg, sender);
    }
}

impl Receive<SHResults> for Client {
    type Msg = ClientMsg;

    fn receive(&mut self, _ctx: &Context<Self::Msg>, _msg: SHResults, _sender: Sender) {}
}

impl Receive<SHRequest> for Client {
    type Msg = ClientMsg;

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: SHRequest, sender: Sender) {
        macro_rules! ensure_vault_exists {
            ( $x:expr, $V:tt, $k:expr ) => {
                if self.vault_exist($x).is_none() {
                    sender
                        .as_ref()
                        .expect(line_error!())
                        .try_tell(
                            SHResults::ReturnControlRequest(ProcResult::$V(ResultMessage::Error(format!(
                                "Failed to find {} vault. Please generate one",
                                $k
                            )))),
                            None,
                        )
                        .expect(line_error!());
                    return;
                }
            };
        }

        match msg {
            SHRequest::CheckVault(vpath) => {
                let vid = self.derive_vault_id(vpath);
                let res = matches!(self.vault_exist(vid), Some(_));

                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnExistsVault(res), None)
                    .expect(line_error!());
            }
            SHRequest::CheckRecord { location } => {
                let client_str = self.get_client_str();
                let (vid, rid) = self.resolve_location(location);

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                internal.try_tell(InternalMsg::CheckRecord(vid, rid), sender);
            }
            SHRequest::CreateNewVault(location) => {
                let (vid, rid) = self.resolve_location(location);
                let client_str = self.get_client_str();

                self.add_new_vault(vid);

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                internal.try_tell(InternalMsg::CreateVault(vid, rid), sender);
            }
            SHRequest::WriteToVault {
                location,
                payload,
                hint,
            } => {
                let (vid, rid) = self.resolve_location(location);

                let client_str = self.get_client_str();

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                internal.try_tell(InternalMsg::WriteToVault(vid, rid, payload, hint), sender);
            }

            #[cfg(test)]
            SHRequest::ReadFromVault { location } => {
                let (vid, rid) = self.resolve_location(location);

                let client_str = self.get_client_str();

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                internal.try_tell(InternalMsg::ReadFromVault(vid, rid), sender);
            }
            SHRequest::RevokeData { location } => {
                let (vid, rid) = self.resolve_location(location);

                let client_str = self.get_client_str();

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                internal.try_tell(InternalMsg::RevokeData(vid, rid), sender);
            }
            SHRequest::GarbageCollect(vpath) => {
                let vid = self.derive_vault_id(vpath);

                let client_str = self.get_client_str();

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                internal.try_tell(InternalMsg::GarbageCollect(vid), sender);
            }
            SHRequest::ListIds(vpath) => {
                let vid = self.derive_vault_id(vpath);

                let client_str = self.get_client_str();

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                internal.try_tell(InternalMsg::ListIds(vid), sender);
            }

            SHRequest::ReadSnapshot {
                key,
                filename,
                path,
                cid,
                former_cid,
            } => {
                let client_str = self.get_client_str();

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                internal.try_tell(InternalMsg::ReadSnapshot(key, filename, path, cid, former_cid), sender);
            }
            SHRequest::ClearCache { kill } => {
                self.clear_cache();

                let client_str = self.get_client_str();

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                if kill {
                    internal.try_tell(InternalMsg::KillInternal, None);

                    sender
                        .as_ref()
                        .expect(line_error!())
                        .try_tell(SHResults::ReturnClearCache(ResultMessage::Ok(())), None)
                        .expect(line_error!());

                    ctx.stop(ctx.myself());
                } else {
                    internal.try_tell(InternalMsg::ClearCache, sender);
                }
            }
            SHRequest::FillSnapshot => {
                let client_str = self.get_client_str();

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                internal.try_tell(InternalMsg::FillSnapshot { client: self.clone() }, sender)
            }
            SHRequest::WriteSnapshot { key, filename, path } => {
                let snapshot = ctx.select("/user/snapshot/").expect(line_error!());

                snapshot.try_tell(SMsg::WriteSnapshot { key, filename, path }, sender);
            }
            SHRequest::DeleteFromStore(loc) => {
                let (vid, _) = self.resolve_location(loc);

                self.store_delete_item(vid.into());
                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnDeleteStore(StatusMessage::Ok(())), None)
                    .expect(line_error!());
            }
            SHRequest::WriteToStore {
                location,
                payload,
                lifetime,
            } => {
                let (vid, _) = self.resolve_location(location);

                self.write_to_store(vid.into(), payload, lifetime);

                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnWriteStore(StatusMessage::Ok(())), None)
                    .expect(line_error!());
            }
            SHRequest::ReadFromStore { location } => {
                let (vid, _) = self.resolve_location(location);

                let payload = self.read_from_store(vid.into());

                if let Some(payload) = payload {
                    sender
                        .as_ref()
                        .expect(line_error!())
                        .try_tell(SHResults::ReturnReadStore(payload, StatusMessage::Ok(())), None)
                        .expect(line_error!());
                } else {
                    sender
                        .as_ref()
                        .expect(line_error!())
                        .try_tell(
                            SHResults::ReturnReadStore(
                                vec![],
                                StatusMessage::Error("Unable to read from store".into()),
                            ),
                            None,
                        )
                        .expect(line_error!());
                }
            }
            SHRequest::ControlRequest(procedure) => {
                let client_str = self.get_client_str();

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                match procedure {
                    Procedure::SLIP10Generate {
                        output,
                        hint,
                        size_bytes,
                    } => {
                        let (vid, rid) = self.resolve_location(output);

                        if self.vault_exist(vid).is_none() {
                            self.add_new_vault(vid);
                        }

                        internal.try_tell(
                            InternalMsg::SLIP10Generate {
                                vault_id: vid,
                                record_id: rid,
                                hint,
                                size_bytes: size_bytes.unwrap_or(64),
                            },
                            sender,
                        )
                    }
                    Procedure::SLIP10Derive {
                        chain,
                        input: SLIP10DeriveInput::Seed(seed),
                        output,
                        hint,
                    } => {
                        let (seed_vault_id, seed_record_id) = self.resolve_location(seed);
                        ensure_vault_exists!(seed_vault_id, SLIP10Derive, "seed");

                        let (key_vault_id, key_record_id) = self.resolve_location(output);

                        if self.vault_exist(key_vault_id).is_none() {
                            self.add_new_vault(key_vault_id);
                        }

                        internal.try_tell(
                            InternalMsg::SLIP10DeriveFromSeed {
                                chain,
                                seed_vault_id,
                                seed_record_id,
                                key_vault_id,
                                key_record_id,
                                hint,
                            },
                            sender,
                        )
                    }
                    Procedure::SLIP10Derive {
                        chain,
                        input: SLIP10DeriveInput::Key(parent),
                        output,
                        hint,
                    } => {
                        let (parent_vault_id, parent_record_id) = self.resolve_location(parent);
                        ensure_vault_exists!(parent_vault_id, SLIP10Derive, "parent key");

                        let (child_vault_id, child_record_id) = self.resolve_location(output);

                        if self.vault_exist(child_vault_id).is_none() {
                            self.add_new_vault(child_vault_id);
                        }

                        internal.try_tell(
                            InternalMsg::SLIP10DeriveFromKey {
                                chain,
                                parent_vault_id,
                                parent_record_id,
                                child_vault_id,
                                child_record_id,
                                hint,
                            },
                            sender,
                        )
                    }
                    Procedure::BIP39Generate {
                        passphrase,
                        output,
                        hint,
                    } => {
                        let (vault_id, record_id) = self.resolve_location(output);

                        if self.vault_exist(vault_id).is_none() {
                            self.add_new_vault(vault_id);
                        }

                        internal.try_tell(
                            InternalMsg::BIP39Generate {
                                passphrase: passphrase.unwrap_or_else(|| "".into()),
                                vault_id,
                                record_id,
                                hint,
                            },
                            sender,
                        )
                    }
                    Procedure::BIP39Recover {
                        mnemonic,
                        passphrase,
                        output,
                        hint,
                    } => {
                        let (vault_id, record_id) = self.resolve_location(output);

                        if self.vault_exist(vault_id).is_none() {
                            self.add_new_vault(vault_id);
                        }

                        internal.try_tell(
                            InternalMsg::BIP39Recover {
                                mnemonic,
                                passphrase: passphrase.unwrap_or_else(|| "".into()),
                                vault_id,
                                record_id,
                                hint,
                            },
                            sender,
                        )
                    }
                    // Not implemented yet.
                    Procedure::BIP39MnemonicSentence { .. } => unimplemented!(),
                    Procedure::Ed25519PublicKey { private_key } => {
                        let (vault_id, record_id) = self.resolve_location(private_key);
                        internal.try_tell(InternalMsg::Ed25519PublicKey { vault_id, record_id }, sender)
                    }
                    Procedure::Ed25519Sign { private_key, msg } => {
                        let (vault_id, record_id) = self.resolve_location(private_key);
                        internal.try_tell(
                            InternalMsg::Ed25519Sign {
                                vault_id,
                                record_id,
                                msg,
                            },
                            sender,
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
                        ensure_vault_exists!(seed_vault_id, Sr25519Derive, "input");

                        let (key_vault_id, key_record_id) = self.resolve_location(output);

                        if self.vault_exist(key_vault_id).is_none() {
                            self.add_new_vault(key_vault_id);
                        }

                        internal.try_tell(
                            InternalMsg::Sr25519Derive {
                                chain,
                                seed_vault_id,
                                seed_record_id,
                                key_vault_id,
                                key_record_id,
                                hint,
                            },
                            sender,
                        )
                    }
                    Procedure::Sr25519Generate {
                        mnemonic_or_seed,
                        passphrase,
                        output,
                        hint,
                    } => {
                        let (vault_id, record_id) = self.resolve_location(output);

                        if self.vault_exist(vault_id).is_none() {
                            self.add_new_vault(vault_id);
                        }

                        internal.try_tell(
                            InternalMsg::Sr25519Generate {
                                mnemonic_or_seed,
                                passphrase: passphrase.unwrap_or_else(|| "".into()),
                                vault_id,
                                record_id,
                                hint,
                            },
                            sender,
                        )
                    }
                    Procedure::Sr25519PublicKey { keypair } => {
                        let (vault_id, record_id) = self.resolve_location(keypair);
                        internal.try_tell(InternalMsg::Sr25519PublicKey { vault_id, record_id }, sender)
                    }
                    Procedure::Sr25519Sign { keypair, msg } => {
                        let (vault_id, record_id) = self.resolve_location(keypair);
                        internal.try_tell(
                            InternalMsg::Sr25519Sign {
                                vault_id,
                                record_id,
                                msg,
                            },
                            sender,
                        )
                    }
                    // secp256k1
                    Procedure::Secp256k1Generate { output, hint } => {
                        let (vault_id, record_id) = self.resolve_location(output);

                        if self.vault_exist(vault_id).is_none() {
                            self.add_new_vault(vault_id);
                        }

                        internal.try_tell(
                            InternalMsg::Secp256k1Generate {
                                vault_id,
                                record_id,
                                hint,
                            },
                            sender,
                        )
                    }
                    Procedure::Secp256k1PublicKey { private_key } => {
                        let (vault_id, record_id) = self.resolve_location(private_key);
                        internal.try_tell(InternalMsg::Secp256k1PublicKey { vault_id, record_id }, sender)
                    }
                    Procedure::Secp256k1Sign { private_key, msg } => {
                        let (vault_id, record_id) = self.resolve_location(private_key);
                        internal.try_tell(
                            InternalMsg::Secp256k1Sign {
                                vault_id,
                                record_id,
                                msg,
                            },
                            sender,
                        )
                    }
                }
            }
        }
    }
}

impl Receive<InternalResults> for Client {
    type Msg = ClientMsg;

    fn receive(&mut self, _ctx: &Context<Self::Msg>, msg: InternalResults, sender: Sender) {
        match msg {
            InternalResults::ReturnCreateVault(status) => {
                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnCreateVault(status), None)
                    .expect(line_error!());
            }
            InternalResults::ReturnCheckRecord(res) => {
                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnExistsRecord(res), None)
                    .expect(line_error!());
            }

            InternalResults::ReturnReadVault(payload, status) => {
                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnReadVault(payload, status), None)
                    .expect(line_error!());
            }
            InternalResults::ReturnList(list, status) => {
                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnList(list, status), None)
                    .expect(line_error!());
            }
            InternalResults::RebuildCache {
                id,
                vaults,
                store,
                status,
            } => {
                self.clear_cache();

                self.rebuild_cache(id, vaults, store);

                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnReadSnap(status), None)
                    .expect(line_error!());
            }
            InternalResults::ReturnWriteVault(status) => {
                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnWriteVault(status), None)
                    .expect(line_error!());
            }
            InternalResults::ReturnRevoke(status) => {
                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnRevoke(status), None)
                    .expect(line_error!());
            }
            InternalResults::ReturnGarbage(status) => {
                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnGarbage(status), None)
                    .expect(line_error!());
            }
            InternalResults::ReturnWriteSnap(status) => {
                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnWriteSnap(status), None)
                    .expect(line_error!());
            }

            InternalResults::ReturnControlRequest(result) => {
                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnControlRequest(result), None)
                    .expect(line_error!());
            }
            InternalResults::ReturnClearCache(status) => {
                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnClearCache(status), None)
                    .expect(line_error!());
            }
        }
    }
}
