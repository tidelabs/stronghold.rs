// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::type_complexity)]

use riker::actors::*;

use std::{
    collections::{HashMap, HashSet},
    convert::{TryFrom, TryInto},
    ops::Deref,
    path::PathBuf,
};

use engine::vault::{BoxProvider, ClientId, DbView, Key, RecordHint, RecordId, VaultId};

use stronghold_utils::GuardDebug;
use web3::{
    api::Accounts,
    signing::{Key as web3Key, Signature, SigningError},
    types::{Address as Web3Address, TransactionParameters, H256},
};

use crypto::{
    keys::{
        bip39,
        slip10::{self, Chain, Curve, Seed},
    },
    signatures::{ed25519, secp256k1, sr25519},
    utils::rand::fill,
};

use engine::snapshot;

use crate::{
    actors::{snapshot::SMsg, ProcResult},
    internals::Provider,
    line_error,
    state::{
        client::{Client, ClientMsg, Store},
        key_store::KeyStore,
    },
    utils::{ResultMessage, StatusMessage},
};

struct Secp256k1SecretKeyRef<'a>(&'a secp256k1::SecretKey);

impl<'a> web3Key for Secp256k1SecretKeyRef<'a> {
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

    fn address(&self) -> Web3Address {
        let public_key = self.0.public_key();
        let public_key = public_key.to_bytes();

        debug_assert_eq!(public_key[0], 0x04);
        let hash = keccak256(&public_key[1..]);

        Web3Address::from_slice(&hash[12..])
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

/// State for the internal actor used as the runtime.
pub struct InternalActor<P: BoxProvider + Send + Sync + Clone + 'static> {
    client_id: ClientId,
    keystore: KeyStore<P>,
    db: DbView<P>,
}

/// Messages used for the Internal Actor.
#[derive(Clone, GuardDebug)]
pub enum InternalMsg {
    /// Creates a new vault at the given [`VaultId`] and [`RecordId`]
    CreateVault(VaultId, RecordId),
    /// Reads data from a vault at the location of the given [`VaultId`] and [`RecordId`]
    #[cfg(test)]
    ReadFromVault(VaultId, RecordId),
    /// Writes data to a vault at the location of the given [`VaultId`] and [`RecordId`]
    WriteToVault(VaultId, RecordId, Vec<u8>, RecordHint),
    /// Revokes data from a vault at the location of the given [`VaultId`] and [`RecordId`]
    RevokeData(VaultId, RecordId),
    /// Garbage collects a vault at the given [`VaultId`]
    GarbageCollect(VaultId),
    /// Lists ids of the vault at the given [`VaultId`]
    ListIds(VaultId),
    /// Checks to see if a record exists at the given [`VaultId`] and [`RecordId`]
    CheckRecord(VaultId, RecordId),
    /// Reads the snapshot from the file.
    ReadSnapshot(
        snapshot::Key,
        Option<String>,
        Option<PathBuf>,
        ClientId,
        Option<ClientId>,
    ),
    /// Reloads the data from the snapshot.
    ReloadData {
        id: ClientId,
        data: Box<(HashMap<VaultId, Key<Provider>>, DbView<Provider>, Store)>,
        status: StatusMessage,
    },
    /// Clears the cache.
    ClearCache,
    /// Kills the internal actor.
    KillInternal,
    /// Fills the snapshot state with the current internal state.
    FillSnapshot { client: Client },

    /// [`SLIP10Generate`] seed Proc.
    SLIP10Generate {
        vault_id: VaultId,
        record_id: RecordId,
        hint: RecordHint,
        size_bytes: usize,
    },
    /// [`SLIP10DeriveFromSeed`] Proc
    SLIP10DeriveFromSeed {
        chain: Chain,
        seed_vault_id: VaultId,
        seed_record_id: RecordId,
        key_vault_id: VaultId,
        key_record_id: RecordId,
        hint: RecordHint,
    },
    /// [`SLIP10DeriveFromKey`] Proc
    SLIP10DeriveFromKey {
        chain: Chain,
        parent_vault_id: VaultId,
        parent_record_id: RecordId,
        child_vault_id: VaultId,
        child_record_id: RecordId,
        hint: RecordHint,
    },
    /// [`BIP39Generate`] Proc
    BIP39Generate {
        passphrase: String,
        vault_id: VaultId,
        record_id: RecordId,
        hint: RecordHint,
    },
    /// [`BIP39Recover`] Proc
    BIP39Recover {
        mnemonic: String,
        passphrase: String,
        vault_id: VaultId,
        record_id: RecordId,
        hint: RecordHint,
    },
    /// [`Ed25519PublicKey`] Proc
    Ed25519PublicKey { vault_id: VaultId, record_id: RecordId },
    /// [`Ed25519Sign`] Proc
    Ed25519Sign {
        vault_id: VaultId,
        record_id: RecordId,
        msg: Vec<u8>,
    },

    /// [`Sr25519erive`] Proc
    Sr25519Derive {
        chain: Vec<sr25519::DeriveJunction>,
        seed_vault_id: VaultId,
        seed_record_id: RecordId,
        key_vault_id: VaultId,
        key_record_id: RecordId,
        hint: RecordHint,
    },
    /// [`Sr25519Generate`] Proc
    Sr25519Generate {
        mnemonic_or_seed: Option<String>,
        passphrase: String,
        vault_id: VaultId,
        record_id: RecordId,
        hint: RecordHint,
    },
    /// [`Sr25519PublicKey`] Proc
    Sr25519PublicKey { vault_id: VaultId, record_id: RecordId },
    /// [`Sr25519Sign`] Proc
    Sr25519Sign {
        vault_id: VaultId,
        record_id: RecordId,
        msg: Vec<u8>,
    },

    /// [`Secp256k1Generate`] Proc
    Secp256k1Generate {
        vault_id: VaultId,
        record_id: RecordId,
        hint: RecordHint,
    },
    /// [`Secp256k1PublicKey`] Proc
    Secp256k1PublicKey { vault_id: VaultId, record_id: RecordId },
    /// [`Sr25519Sign`] Proc
    Secp256k1Sign {
        vault_id: VaultId,
        record_id: RecordId,
        msg: Box<[u8; 32]>,
    },

    /// Sign transaction using web3 instance.
    Web3SignTransaction {
        vault_id: VaultId,
        record_id: RecordId,
        accounts: Accounts<web3::transports::Http>,
        tx: TransactionParameters,
    },
}

/// Return messages used internally by the client.
#[derive(Clone, GuardDebug)]
pub enum InternalResults {
    ReturnCreateVault(StatusMessage),
    ReturnWriteVault(StatusMessage),
    ReturnReadVault(Vec<u8>, StatusMessage),
    ReturnCheckRecord(bool),
    ReturnRevoke(StatusMessage),
    ReturnGarbage(StatusMessage),
    ReturnList(Vec<(RecordId, RecordHint)>, StatusMessage),
    ReturnWriteSnap(StatusMessage),
    ReturnControlRequest(ProcResult),
    RebuildCache {
        id: ClientId,
        vaults: HashSet<VaultId>,
        store: Store,
        status: StatusMessage,
    },
    ReturnClearCache(StatusMessage),
}

impl ActorFactoryArgs<ClientId> for InternalActor<Provider> {
    fn create_args(id: ClientId) -> Self {
        let db = DbView::new();
        let keystore = KeyStore::new();

        Self {
            db,
            keystore,
            client_id: id,
        }
    }
}

impl Actor for InternalActor<Provider> {
    type Msg = InternalMsg;

    fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        self.receive(ctx, msg, sender);
    }
}

impl Receive<InternalMsg> for InternalActor<Provider> {
    type Msg = InternalMsg;

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        match msg {
            InternalMsg::CreateVault(vid, _rid) => {
                let key = self.keystore.create_key(vid);
                self.db.init_vault(&key, vid).expect(line_error!());

                let cstr: String = self.client_id.into();

                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());
                client.try_tell(
                    ClientMsg::InternalResults(InternalResults::ReturnCreateVault(StatusMessage::OK)),
                    sender,
                );
            }
            #[cfg(test)]
            InternalMsg::ReadFromVault(vid, rid) => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());

                if let Some(key) = self.keystore.get_key(vid) {
                    let mut data: Vec<u8> = Vec::new();

                    self.db
                        .get_guard(&key, vid, rid, |gdata| {
                            let gdata = gdata.borrow();
                            data.extend_from_slice(&*gdata);

                            Ok(())
                        })
                        .expect(line_error!());

                    self.keystore.insert_key(vid, key);

                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnReadVault(data, StatusMessage::OK)),
                        sender,
                    );
                } else {
                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnReadVault(
                            vec![],
                            StatusMessage::Error("Vault does not exist.".into()),
                        )),
                        sender,
                    );
                }
            }
            InternalMsg::CheckRecord(vid, rid) => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());
                if let Some(key) = self.keystore.get_key(vid) {
                    let res = self.db.contains_record(&key, vid, rid);

                    self.keystore.insert_key(vid, key);

                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnCheckRecord(res)),
                        sender,
                    );
                } else {
                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnCheckRecord(false)),
                        sender,
                    );
                }
            }
            InternalMsg::WriteToVault(vid, rid, payload, hint) => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());

                if let Some(key) = self.keystore.get_key(vid) {
                    self.db
                        .write(&key, vid, rid, payload.as_slice(), hint)
                        .expect(line_error!());

                    self.keystore.insert_key(vid, key);

                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnWriteVault(StatusMessage::OK)),
                        sender,
                    );
                } else {
                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnWriteVault(StatusMessage::Error(
                            "Vault does not exist".into(),
                        ))),
                        sender,
                    );
                }
            }

            InternalMsg::RevokeData(vid, rid) => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());
                if let Some(key) = self.keystore.get_key(vid) {
                    self.db.revoke_record(&key, vid, rid).expect(line_error!());

                    self.keystore.insert_key(vid, key);

                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnRevoke(StatusMessage::OK)),
                        sender,
                    );
                } else {
                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnRevoke(StatusMessage::Error(
                            "Failed to revoke record, vault wasn't found".into(),
                        ))),
                        sender,
                    );
                }
            }
            InternalMsg::GarbageCollect(vid) => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());
                if let Some(key) = self.keystore.get_key(vid) {
                    self.db.garbage_collect_vault(&key, vid).expect(line_error!());

                    self.keystore.insert_key(vid, key);

                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnGarbage(StatusMessage::OK)),
                        sender,
                    );
                } else {
                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnGarbage(StatusMessage::Error(
                            "Failed to garbage collect, vault wasn't found".into(),
                        ))),
                        sender,
                    );
                }
            }
            InternalMsg::ListIds(vid) => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());
                if let Some(key) = self.keystore.get_key(vid) {
                    let ids = self.db.list_hints_and_ids(&key, vid);

                    self.keystore.insert_key(vid, key);

                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnList(ids, StatusMessage::OK)),
                        sender,
                    );
                } else {
                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnList(
                            vec![],
                            StatusMessage::Error("Failed to get list, vault wasn't found".into()),
                        )),
                        sender,
                    );
                }
            }
            InternalMsg::ReloadData { id, data, status } => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());

                let (keystore, state, store) = *data;

                let vids = keystore.keys().copied().collect::<HashSet<VaultId>>();

                self.keystore.rebuild_keystore(keystore);

                self.db = state;

                client.try_tell(
                    ClientMsg::InternalResults(InternalResults::RebuildCache {
                        id,
                        vaults: vids,
                        status,
                        store,
                    }),
                    sender,
                );
            }

            InternalMsg::ReadSnapshot(key, filename, path, id, fid) => {
                let snapshot = ctx.select("/user/snapshot/").expect(line_error!());
                snapshot.try_tell(
                    SMsg::ReadFromSnapshot {
                        key,
                        filename,
                        path,
                        id,
                        fid,
                    },
                    sender,
                );
            }
            InternalMsg::ClearCache => {
                self.keystore.clear_keys();
                self.db.clear().expect(line_error!());

                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());
                client.try_tell(
                    ClientMsg::InternalResults(InternalResults::ReturnClearCache(StatusMessage::OK)),
                    sender,
                );
            }
            InternalMsg::KillInternal => {
                ctx.stop(ctx.myself());
            }
            InternalMsg::SLIP10Generate {
                vault_id,
                record_id,
                hint,
                size_bytes,
            } => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());

                let key = if !self.keystore.vault_exists(vault_id) {
                    let key = self.keystore.create_key(vault_id);
                    self.db.init_vault(&key, vault_id).expect(line_error!());

                    key
                } else {
                    self.keystore.get_key(vault_id).expect(line_error!())
                };

                self.keystore.insert_key(vault_id, key.clone());

                let mut seed = vec![0u8; size_bytes];
                fill(&mut seed).expect(line_error!());

                self.db
                    .write(&key, vault_id, record_id, &seed, hint)
                    .expect(line_error!());

                client.try_tell(
                    ClientMsg::InternalResults(InternalResults::ReturnControlRequest(ProcResult::SLIP10Generate(
                        StatusMessage::OK,
                    ))),
                    sender,
                );
            }
            InternalMsg::SLIP10DeriveFromSeed {
                chain,
                seed_vault_id,
                seed_record_id,
                key_vault_id,
                key_record_id,
                hint,
            } => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());

                match self.keystore.get_key(seed_vault_id) {
                    Some(seed_key) => {
                        self.keystore.insert_key(seed_vault_id, seed_key.clone());
                        let dk_key = if !self.keystore.vault_exists(key_vault_id) {
                            let key = self.keystore.create_key(key_vault_id);
                            self.db.init_vault(&key, key_vault_id).expect(line_error!());

                            key
                        } else {
                            self.keystore.get_key(key_vault_id).expect(line_error!())
                        };
                        self.keystore.insert_key(key_vault_id, dk_key.clone());

                        self.db
                            .exec_proc(
                                &seed_key,
                                seed_vault_id,
                                seed_record_id,
                                &dk_key,
                                key_vault_id,
                                key_record_id,
                                hint,
                                |gdata| {
                                    let dk = Seed::from_bytes(&gdata.borrow())
                                        .derive(Curve::Ed25519, &chain)
                                        .expect(line_error!());

                                    let data: Vec<u8> = dk.into();

                                    client.try_tell(
                                        ClientMsg::InternalResults(InternalResults::ReturnControlRequest(
                                            ProcResult::SLIP10Derive(ResultMessage::Ok(dk.chain_code())),
                                        )),
                                        sender,
                                    );

                                    Ok(data)
                                },
                            )
                            .expect(line_error!());
                    }
                    _ => client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnControlRequest(ProcResult::SLIP10Derive(
                            ResultMessage::Error("Failed to access vault".into()),
                        ))),
                        sender,
                    ),
                }
            }
            InternalMsg::SLIP10DeriveFromKey {
                chain,
                parent_vault_id,
                parent_record_id,
                child_vault_id,
                child_record_id,
                hint,
            } => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());

                match self.keystore.get_key(parent_vault_id) {
                    Some(parent_key) => {
                        self.keystore.insert_key(parent_vault_id, parent_key.clone());
                        let child_key = if !self.keystore.vault_exists(child_vault_id) {
                            let key = self.keystore.create_key(child_vault_id);
                            self.db.init_vault(&key, child_vault_id).expect(line_error!());

                            key
                        } else {
                            self.keystore.get_key(child_vault_id).expect(line_error!())
                        };

                        self.keystore.insert_key(child_vault_id, child_key.clone());

                        self.db
                            .exec_proc(
                                &parent_key,
                                parent_vault_id,
                                parent_record_id,
                                &child_key,
                                child_vault_id,
                                child_record_id,
                                hint,
                                |parent| {
                                    let parent = slip10::Key::try_from(&*parent.borrow()).expect(line_error!());
                                    let dk = parent.derive(&chain).expect(line_error!());

                                    let data: Vec<u8> = dk.into();

                                    client.try_tell(
                                        ClientMsg::InternalResults(InternalResults::ReturnControlRequest(
                                            ProcResult::SLIP10Derive(ResultMessage::Ok(dk.chain_code())),
                                        )),
                                        sender,
                                    );

                                    Ok(data)
                                },
                            )
                            .expect(line_error!());
                    }
                    _ => client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnControlRequest(ProcResult::SLIP10Derive(
                            ResultMessage::Error("Failed to access vault".into()),
                        ))),
                        sender,
                    ),
                }
            }
            InternalMsg::BIP39Generate {
                passphrase,
                vault_id,
                record_id,
                hint,
            } => {
                let mut entropy = [0u8; 32];
                fill(&mut entropy).expect(line_error!());

                let mnemonic = bip39::wordlist::encode(
                    &entropy,
                    &bip39::wordlist::ENGLISH, // TODO: make this user configurable
                )
                .expect(line_error!());

                let mut seed = [0u8; 64];
                bip39::mnemonic_to_seed(&mnemonic, &passphrase, &mut seed);

                let key = if !self.keystore.vault_exists(vault_id) {
                    let k = self.keystore.create_key(vault_id);
                    self.db.init_vault(&k, vault_id).expect(line_error!());

                    k
                } else {
                    self.keystore.get_key(vault_id).expect(line_error!())
                };

                self.keystore.insert_key(vault_id, key.clone());

                // TODO: also store the mnemonic to be able to export it in the
                // BIP39MnemonicSentence message
                self.db
                    .write(&key, vault_id, record_id, &seed, hint)
                    .expect(line_error!());

                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());
                client.try_tell(
                    ClientMsg::InternalResults(InternalResults::ReturnControlRequest(ProcResult::BIP39Generate(
                        StatusMessage::OK,
                    ))),
                    sender,
                );
            }
            InternalMsg::BIP39Recover {
                mnemonic,
                passphrase,
                vault_id,
                record_id,
                hint,
            } => {
                let key = if !self.keystore.vault_exists(vault_id) {
                    let k = self.keystore.create_key(vault_id);
                    self.db.init_vault(&k, vault_id).expect(line_error!());

                    k
                } else {
                    self.keystore.get_key(vault_id).expect(line_error!())
                };

                self.keystore.insert_key(vault_id, key.clone());

                let mut seed = [0u8; 64];
                bip39::mnemonic_to_seed(&mnemonic, &passphrase, &mut seed);

                // TODO: also store the mnemonic to be able to export it in the
                // BIP39MnemonicSentence message
                self.db
                    .write(&key, vault_id, record_id, &seed, hint)
                    .expect(line_error!());

                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());
                client.try_tell(
                    ClientMsg::InternalResults(InternalResults::ReturnControlRequest(ProcResult::BIP39Recover(
                        StatusMessage::OK,
                    ))),
                    sender,
                );
            }
            InternalMsg::Ed25519PublicKey { vault_id, record_id } => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());

                if let Some(key) = self.keystore.get_key(vault_id) {
                    self.keystore.insert_key(vault_id, key.clone());

                    self.db
                        .get_guard(&key, vault_id, record_id, |data| {
                            let raw = data.borrow();
                            let mut raw = (*raw).to_vec();

                            if raw.len() < 32 {
                                client.try_tell(
                                    ClientMsg::InternalResults(InternalResults::ReturnControlRequest(
                                        ProcResult::Ed25519PublicKey(ResultMessage::Error(
                                            "Incorrect number of key bytes".into(),
                                        )),
                                    )),
                                    sender.clone(),
                                );
                            }
                            raw.truncate(32);
                            let mut bs = [0; 32];
                            bs.copy_from_slice(&raw);
                            let sk = ed25519::SecretKey::from_le_bytes(bs).expect(line_error!());
                            let pk = sk.public_key();

                            client.try_tell(
                                ClientMsg::InternalResults(InternalResults::ReturnControlRequest(
                                    ProcResult::Ed25519PublicKey(ResultMessage::Ok(pk.to_compressed_bytes())),
                                )),
                                sender,
                            );

                            Ok(())
                        })
                        .expect(line_error!());
                } else {
                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnControlRequest(
                            ProcResult::Ed25519PublicKey(ResultMessage::Error("Failed to access vault".into())),
                        )),
                        sender,
                    )
                }
            }
            InternalMsg::Ed25519Sign {
                vault_id,
                record_id,
                msg,
            } => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());
                if let Some(pkey) = self.keystore.get_key(vault_id) {
                    self.keystore.insert_key(vault_id, pkey.clone());

                    self.db
                        .get_guard(&pkey, vault_id, record_id, |data| {
                            let raw = data.borrow();
                            let mut raw = (*raw).to_vec();

                            if raw.len() <= 32 {
                                client.try_tell(
                                    ClientMsg::InternalResults(InternalResults::ReturnControlRequest(
                                        ProcResult::Ed25519Sign(ResultMessage::Error(
                                            "incorrect number of key bytes".into(),
                                        )),
                                    )),
                                    sender.clone(),
                                );
                            }
                            raw.truncate(32);
                            let mut bs = [0; 32];
                            bs.copy_from_slice(&raw);
                            let sk = ed25519::SecretKey::from_le_bytes(bs).expect(line_error!());

                            let sig = sk.sign(&msg);

                            client.try_tell(
                                ClientMsg::InternalResults(InternalResults::ReturnControlRequest(
                                    ProcResult::Ed25519Sign(ResultMessage::Ok(sig.to_bytes())),
                                )),
                                sender,
                            );

                            Ok(())
                        })
                        .expect(line_error!());
                } else {
                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnControlRequest(ProcResult::Ed25519Sign(
                            ResultMessage::Error("Failed to access vault".into()),
                        ))),
                        sender,
                    )
                }
            }

            // sr25519
            InternalMsg::Sr25519Derive {
                chain,
                seed_vault_id,
                seed_record_id,
                key_vault_id,
                key_record_id,
                hint,
            } => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());

                match self.keystore.get_key(seed_vault_id) {
                    Some(seed_key) => {
                        self.keystore.insert_key(seed_vault_id, seed_key.clone());
                        let dk_key = if !self.keystore.vault_exists(key_vault_id) {
                            let key = self.keystore.create_key(key_vault_id);
                            self.db.init_vault(&key, key_vault_id).expect(line_error!());

                            key
                        } else {
                            self.keystore.get_key(key_vault_id).expect(line_error!())
                        };
                        self.keystore.insert_key(key_vault_id, dk_key.clone());

                        self.db
                            .exec_proc(
                                &seed_key,
                                seed_vault_id,
                                seed_record_id,
                                &dk_key,
                                key_vault_id,
                                key_record_id,
                                hint,
                                |gdata| {
                                    let dk = sr25519::KeyPair::from_seed(&gdata.borrow())
                                        .derive(chain.into_iter(), None)
                                        .expect(line_error!());

                                    let data = dk.seed().to_vec();

                                    client.try_tell(
                                        ClientMsg::InternalResults(InternalResults::ReturnControlRequest(
                                            ProcResult::Sr25519Derive(StatusMessage::OK),
                                        )),
                                        sender,
                                    );

                                    Ok(data)
                                },
                            )
                            .expect(line_error!());
                    }
                    _ => client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnControlRequest(ProcResult::Sr25519Derive(
                            ResultMessage::Error("Failed to access vault".into()),
                        ))),
                        sender,
                    ),
                }
            }
            InternalMsg::Sr25519Generate {
                mnemonic_or_seed,
                passphrase,
                vault_id,
                record_id,
                hint,
            } => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());

                let keypair = match mnemonic_or_seed {
                    Some(m) => sr25519::KeyPair::from_string(&m, Some(&passphrase)),
                    None => {
                        let mut entropy = [0u8; 32];
                        fill(&mut entropy).expect(line_error!());

                        let mnemonic =
                            bip39::wordlist::encode(&entropy, &bip39::wordlist::ENGLISH).expect(line_error!());

                        sr25519::KeyPair::from_string(&mnemonic, Some(&passphrase))
                    }
                };

                let key = if !self.keystore.vault_exists(vault_id) {
                    let k = self.keystore.create_key(vault_id);
                    self.db.init_vault(&k, vault_id).expect(line_error!());

                    k
                } else {
                    self.keystore.get_key(vault_id).expect(line_error!())
                };

                self.keystore.insert_key(vault_id, key.clone());

                match keypair {
                    Ok(keypair) => {
                        self.db
                            .write(&key, vault_id, record_id, &keypair.seed(), hint)
                            .expect(line_error!());

                        client.try_tell(
                            ClientMsg::InternalResults(InternalResults::ReturnControlRequest(
                                ProcResult::Sr25519Generate(StatusMessage::OK),
                            )),
                            sender,
                        );
                    }
                    Err(e) => {
                        client.try_tell(
                            ClientMsg::InternalResults(InternalResults::ReturnControlRequest(ProcResult::Error(
                                format!("failed to generate key pair: {}", e.to_string()),
                            ))),
                            sender,
                        );
                    }
                }
            }
            InternalMsg::Sr25519PublicKey { vault_id, record_id } => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());

                if let Some(key) = self.keystore.get_key(vault_id) {
                    self.keystore.insert_key(vault_id, key.clone());

                    self.db
                        .get_guard(&key, vault_id, record_id, |data| {
                            let raw = data.borrow();

                            if raw.len() != 64 {
                                client.try_tell(
                                    ClientMsg::InternalResults(InternalResults::ReturnControlRequest(
                                        ProcResult::Sr25519PublicKey(ResultMessage::Error(
                                            "Incorrect number of key bytes".into(),
                                        )),
                                    )),
                                    sender.clone(),
                                );
                            }

                            let keypair = sr25519::KeyPair::from_seed(&raw);
                            let pk = keypair.public_key();

                            client.try_tell(
                                ClientMsg::InternalResults(InternalResults::ReturnControlRequest(
                                    ProcResult::Sr25519PublicKey(ResultMessage::Ok(pk)),
                                )),
                                sender,
                            );

                            Ok(())
                        })
                        .expect(line_error!());
                } else {
                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnControlRequest(
                            ProcResult::Sr25519PublicKey(ResultMessage::Error("Failed to access vault".into())),
                        )),
                        sender,
                    )
                }
            }
            InternalMsg::Sr25519Sign {
                vault_id,
                record_id,
                msg,
            } => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());
                if let Some(pkey) = self.keystore.get_key(vault_id) {
                    self.keystore.insert_key(vault_id, pkey.clone());

                    self.db
                        .get_guard(&pkey, vault_id, record_id, |data| {
                            let raw = data.borrow();

                            if raw.len() != 64 {
                                client.try_tell(
                                    ClientMsg::InternalResults(InternalResults::ReturnControlRequest(
                                        ProcResult::Sr25519Sign(ResultMessage::Error(
                                            "incorrect number of key bytes".into(),
                                        )),
                                    )),
                                    sender.clone(),
                                );
                            }

                            let keypair = sr25519::KeyPair::from_seed(&raw);
                            let sig = keypair.sign(&msg);

                            client.try_tell(
                                ClientMsg::InternalResults(InternalResults::ReturnControlRequest(
                                    ProcResult::Sr25519Sign(ResultMessage::Ok(sig)),
                                )),
                                sender,
                            );

                            Ok(())
                        })
                        .expect(line_error!());
                } else {
                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnControlRequest(ProcResult::Sr25519Sign(
                            ResultMessage::Error("Failed to access vault".into()),
                        ))),
                        sender,
                    )
                }
            }

            InternalMsg::Secp256k1Generate {
                vault_id,
                record_id,
                hint,
            } => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());

                let mut key = vec![0u8; secp256k1::SECRET_KEY_LENGTH];
                fill(&mut key).expect(line_error!());
                let private_key = secp256k1::SecretKey::from_bytes(&key.try_into().unwrap()).expect(line_error!());

                let key = if !self.keystore.vault_exists(vault_id) {
                    let k = self.keystore.create_key(vault_id);
                    self.db.init_vault(&k, vault_id).expect(line_error!());

                    k
                } else {
                    self.keystore.get_key(vault_id).expect(line_error!())
                };

                self.keystore.insert_key(vault_id, key.clone());

                self.db
                    .write(&key, vault_id, record_id, &private_key.to_bytes(), hint)
                    .expect(line_error!());

                client.try_tell(
                    ClientMsg::InternalResults(InternalResults::ReturnControlRequest(ProcResult::Secp256k1Generate(
                        StatusMessage::OK,
                    ))),
                    sender,
                );
            }
            InternalMsg::Secp256k1PublicKey { vault_id, record_id } => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());

                if let Some(key) = self.keystore.get_key(vault_id) {
                    self.keystore.insert_key(vault_id, key.clone());

                    self.db
                        .get_guard(&key, vault_id, record_id, |data| {
                            let raw = data.borrow();

                            if raw.len() != 32 {
                                client.try_tell(
                                    ClientMsg::InternalResults(InternalResults::ReturnControlRequest(
                                        ProcResult::Secp256k1PublicKey(ResultMessage::Error(
                                            "Incorrect number of private key bytes".into(),
                                        )),
                                    )),
                                    sender.clone(),
                                );
                            }

                            let private_key =
                                secp256k1::SecretKey::from_bytes(&raw.deref().try_into().expect(line_error!()))
                                    .expect(line_error!());
                            let pk = private_key.public_key();

                            client.try_tell(
                                ClientMsg::InternalResults(InternalResults::ReturnControlRequest(
                                    ProcResult::Secp256k1PublicKey(ResultMessage::Ok(pk)),
                                )),
                                sender,
                            );

                            Ok(())
                        })
                        .expect(line_error!());
                } else {
                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnControlRequest(
                            ProcResult::Secp256k1PublicKey(ResultMessage::Error("Failed to access vault".into())),
                        )),
                        sender,
                    )
                }
            }
            InternalMsg::Secp256k1Sign {
                vault_id,
                record_id,
                msg,
            } => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());
                if let Some(pkey) = self.keystore.get_key(vault_id) {
                    self.keystore.insert_key(vault_id, pkey.clone());

                    self.db
                        .get_guard(&pkey, vault_id, record_id, |data| {
                            let raw = data.borrow();

                            if raw.len() != 32 {
                                client.try_tell(
                                    ClientMsg::InternalResults(InternalResults::ReturnControlRequest(
                                        ProcResult::Secp256k1Sign(ResultMessage::Error(
                                            "incorrect number of private key bytes".into(),
                                        )),
                                    )),
                                    sender.clone(),
                                );
                            }

                            let private_key =
                                secp256k1::SecretKey::from_bytes(&raw.deref().try_into().expect(line_error!()))
                                    .expect(line_error!());
                            let (sig, recovery_id) = private_key.sign(&msg);

                            client.try_tell(
                                ClientMsg::InternalResults(InternalResults::ReturnControlRequest(
                                    ProcResult::Secp256k1Sign(ResultMessage::Ok((sig, recovery_id))),
                                )),
                                sender,
                            );

                            Ok(())
                        })
                        .expect(line_error!());
                } else {
                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnControlRequest(ProcResult::Secp256k1Sign(
                            ResultMessage::Error("Failed; to access vault".into()),
                        ))),
                        sender,
                    )
                }
            }

            // web3
            InternalMsg::Web3SignTransaction {
                vault_id,
                record_id,
                accounts,
                tx,
            } => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());
                if let Some(pkey) = self.keystore.get_key(vault_id) {
                    self.keystore.insert_key(vault_id, pkey.clone());

                    self.db
                        .get_guard(&pkey, vault_id, record_id, |data| {
                            let raw = data.borrow();

                            if raw.len() != 32 {
                                client.try_tell(
                                    ClientMsg::InternalResults(InternalResults::ReturnControlRequest(
                                        ProcResult::Web3SignTransaction(ResultMessage::Error(
                                            "incorrect number of private key bytes".into(),
                                        )),
                                    )),
                                    sender.clone(),
                                );
                            }

                            let private_key =
                                secp256k1::SecretKey::from_bytes(&raw.deref().try_into().expect(line_error!()))
                                    .expect(line_error!());
                            let key = Secp256k1SecretKeyRef(&private_key);

                            match futures::executor::block_on(accounts.sign_transaction(tx, key)) {
                                Ok(signed_transaction) => {
                                    client.try_tell(
                                        ClientMsg::InternalResults(InternalResults::ReturnControlRequest(
                                            ProcResult::Web3SignTransaction(ResultMessage::Ok(signed_transaction)),
                                        )),
                                        sender,
                                    );
                                }
                                Err(e) => {
                                    client.try_tell(
                                        ClientMsg::InternalResults(InternalResults::ReturnControlRequest(
                                            ProcResult::Web3SignTransaction(ResultMessage::Error(format!(
                                                "failed to sign transaction: {}",
                                                e.to_string()
                                            ))),
                                        )),
                                        sender.clone(),
                                    );
                                }
                            }

                            Ok(())
                        })
                        .expect(line_error!());
                } else {
                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnControlRequest(ProcResult::Secp256k1Sign(
                            ResultMessage::Error("Failed; to access vault".into()),
                        ))),
                        sender,
                    )
                }
            }

            InternalMsg::FillSnapshot { client } => {
                let snapshot = ctx.select("/user/snapshot/").expect(line_error!());

                let keys = self.keystore.get_data();
                let db = self.db.clone();
                let store = client.store;
                let id = client.client_id;

                snapshot.try_tell(
                    SMsg::FillSnapshot {
                        id,
                        data: Box::from((keys, db, store)),
                    },
                    sender,
                );
            }
        }
    }
}
