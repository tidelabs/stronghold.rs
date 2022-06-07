// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// No std maybe for later
// #![no_std]

mod boxed;
pub mod locked_memory;
pub mod memories;
mod types;
pub mod utils;

pub use thiserror::Error as DeriveError;
pub use types::Bytes;

/// The memory types of this crate shall return this message when trying to debug them
pub const DEBUG_MSG: &str = "Content of Locked Memory is hidden";

/// The different types of Error that may be encountered while using this crate
#[derive(Debug, DeriveError)]
pub enum MemoryError {
    #[error("Encryption Error")]
    EncryptionError,

    #[error("Decryption Error")]
    DecryptionError,

    #[error("Illegal non-contiguous size")]
    NCSizeNotAllowed,

    #[error("Lock unavailable")]
    LockNotAvailable,

    #[error("File System Error")]
    FileSystemError,

    #[error("Illegal zero-sized value provided")]
    ZeroSizedNotAllowed,
}

/// A simple trait to force the types to call `zeroize()` when dropping
pub trait ZeroizeOnDrop {}
