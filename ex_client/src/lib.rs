// Stronghold client for Stronghold_ex

mod internal;
mod procs;
mod utils;

use thiserror::Error as DeriveError;

pub use engine::{
    vault::{ClientId, RecordHint},
    Error as EngineError,
};

pub use internal::{
    derive_vault_id, naive_kdf, resolve_location, Key, KeyStore, Provider, SecureBucket, Snapshot, SnapshotState,
};
pub use procs::{public_key_inner, sr25519_sign_inner};
pub use utils::{LoadFromPath, Location};

#[macro_export]
macro_rules! line_error {
    () => {
        concat!("Error at ", file!(), ":", line!())
    };
    ($str:expr) => {
        concat!($str, " @", file!(), ":", line!())
    };
}
pub type Result<T> = anyhow::Result<T, Error>;

/// Stronghold Client error block.
#[derive(DeriveError, Debug)]
pub enum Error {
    #[error("Id Error")]
    IDError,

    #[error("Engine Error: {0}")]
    EngineError(#[from] engine::Error),

    #[error("Id Conversion Error ({0})")]
    IdConversionError(String),

    #[error("Path Error: ({0})")]
    PathError(String),

    #[error("Keystore Access Error: ({0})")]
    KeyStoreError(String),

    #[error("Could not load client by path ({0})")]
    LoadClientByPathError(String),

    #[error("Couldn't convert signature")]
    SignatureError,

    #[error("Crypto error: {0}")]
    CryptoError(String),
}

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
