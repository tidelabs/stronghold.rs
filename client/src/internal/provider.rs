// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::ops::Deref;

use crypto::{
    ciphers::{chacha::XChaCha20Poly1305, traits::Aead},
    utils::rand::fill,
};

use engine::vault::{BoxProvider, Key};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// An implementation of the Vault's [`BoxProvider`] type.  Used to encrypt and decrypt the data in this Stronghold.
#[derive(Ord, PartialEq, Eq, PartialOrd, Clone, Debug, Serialize, Deserialize, Default, Zeroize)]

pub struct Provider;
impl Provider {
    /// Nonce length.
    const NONCE_LEN: usize = XChaCha20Poly1305::NONCE_LENGTH;
    /// Tag Length.
    const TAG_LEN: usize = XChaCha20Poly1305::TAG_LENGTH;
}

impl Unpin for Provider {}

impl BoxProvider for Provider {
    type Error = crypto::Error;

    /// Key size.
    fn box_key_len() -> usize {
        32
    }

    /// Nonce length plus Tag length.
    fn box_overhead() -> usize {
        Self::NONCE_LEN + Self::TAG_LEN
    }

    /// Encrypts the data using the xchacha20-poly1305 algorithm.
    fn box_seal(key: &Key<Self>, ad: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let mut cipher = vec![0u8; data.len()];

        let mut tag = vec![0u8; 16];
        let mut nonce: [u8; 24] = [0u8; Self::NONCE_LEN];

        Self::random_buf(&mut nonce)?;

        // Key should impl Deref
        let key = key.key.borrow();

        XChaCha20Poly1305::try_encrypt(key.deref(), &nonce, ad, data, &mut cipher, &mut tag)?;

        let r#box = [tag.to_vec(), nonce.to_vec(), cipher].concat();

        Ok(r#box)
    }

    /// Decrypts the data using the xchacha20-poly1305 algorithm.
    fn box_open(key: &Key<Self>, ad: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let (tag, ct) = data.split_at(Self::TAG_LEN);
        let (nonce, cipher) = ct.split_at(Self::NONCE_LEN);

        let mut plain = vec![0; cipher.len()];

        // Key should impl Deref
        let key = key.key.borrow();

        XChaCha20Poly1305::try_decrypt(key.deref(), nonce, ad, &mut plain, cipher, tag)?;

        Ok(plain)
    }

    /// fills a buffer with random bytes.
    fn random_buf(buf: &mut [u8]) -> Result<(), Self::Error> {
        fill(buf)
    }
}
