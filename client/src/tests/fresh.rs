// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crypto::{
    keys::slip10::Chain, signatures::secp256k1::Chain as SChain, signatures::sr25519::DeriveJunction, utils::rand::fill,
};
pub use stronghold_utils::test_utils::{self, fresh::*};

use crate::{Location, RecordHint};

/// Creates a random [`RecordHint`]
pub fn record_hint() -> RecordHint {
    let mut bs = [0; 24];
    fill(&mut bs).expect("Unable to fill record hint");
    bs.into()
}

/// Generates a random [`Location`].
pub fn location() -> Location {
    Location::generic(bytestring(), bytestring())
}

/// generates a random string based on a coinflip.
pub fn passphrase() -> Option<String> {
    if coinflip() {
        Some(string())
    } else {
        None
    }
}

/// Creates a random hd_path.
pub fn hd_path() -> (String, Chain) {
    let mut s = "m".to_string();
    let mut is = vec![];
    while coinflip() {
        let i = rand::random::<u32>() & 0x7fffff;
        s.push_str(&format!("/{}'", i.to_string()));
        is.push(i);
    }
    (s, Chain::from_u32_hardened(is))
}

/// Creates a random hd_path.
pub fn hd_path_schain() -> (String, SChain) {
    let mut s = "m".to_string();
    let mut is = vec![];
    while coinflip() {
        let i = rand::random::<u32>() & 0x7fffff;
        s.push_str(&format!("/{}'", i.to_string()));
        is.push(i);
    }
    (s, SChain::from_u32_hardened(is))
}

pub fn sr25519_chain() -> Vec<DeriveJunction> {
    let mut chain = Vec::new();
    while coinflip() {
        let b = rand::random::<[u8; 32]>();
        chain.push(if coinflip() {
            DeriveJunction::Hard(b)
        } else {
            DeriveJunction::Soft(b)
        });
    }
    chain
}
