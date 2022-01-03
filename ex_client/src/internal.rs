mod key_store;
mod provider;
mod secure;
mod snapshot;

pub use crate::utils::{LoadFromPath, Location};
pub use engine::{
    store::Cache,
    vault::{ClientId, Key, RecordHint},
};
pub use key_store::KeyStore;
pub use provider::Provider;
pub use secure::{derive_vault_id, resolve_location, SecureBucket};
pub use snapshot::{naive_kdf, Snapshot, SnapshotState};

pub type Store = Cache<Vec<u8>, Vec<u8>>;
