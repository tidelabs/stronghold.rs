// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use super::fresh;
use crate::{ProcResult, Procedure, ResultMessage, SLIP10DeriveInput, Stronghold};
use crypto::{keys::bip39, utils::rand::fill};

async fn setup_stronghold() -> (Vec<u8>, Stronghold) {
    let cp = fresh::bytestring();

    let s = Stronghold::init_stronghold_system(cp.clone(), vec![]).await.unwrap();
    (cp, s)
}

#[actix::test]
async fn usecase_ed25519() {
    let (_cp, sh) = setup_stronghold().await;

    let seed = fresh::location();

    if fresh::coinflip() {
        let size_bytes = if fresh::coinflip() {
            Some(fresh::usize(1024))
        } else {
            None
        };

        match sh
            .runtime_exec(Procedure::SLIP10Generate {
                size_bytes,
                output: seed.clone(),
                hint: fresh::record_hint(),
            })
            .await
        {
            ProcResult::SLIP10Generate(ResultMessage::OK) => (),
            r => panic!("unexpected result: {:?}", r),
        }
    } else {
        match sh
            .runtime_exec(Procedure::BIP39Generate {
                passphrase: fresh::passphrase(),
                output: seed.clone(),
                hint: fresh::record_hint(),
            })
            .await
        {
            ProcResult::BIP39Generate(ResultMessage::OK) => (),
            r => panic!("unexpected result: {:?}", r),
        }
    }

    let (_path, chain) = fresh::hd_path();
    let key = fresh::location();

    match sh
        .runtime_exec(Procedure::SLIP10Derive {
            chain,
            input: SLIP10DeriveInput::Seed(seed),
            output: key.clone(),
            hint: fresh::record_hint(),
        })
        .await
    {
        ProcResult::SLIP10Derive(ResultMessage::Ok(_)) => (),
        r => panic!("unexpected result: {:?}", r),
    };

    let pk = match sh
        .runtime_exec(Procedure::Ed25519PublicKey {
            private_key: key.clone(),
        })
        .await
    {
        ProcResult::Ed25519PublicKey(ResultMessage::Ok(pk)) => pk,
        r => panic!("unexpected result: {:?}", r),
    };

    let msg = fresh::bytestring();

    let sig = match sh
        .runtime_exec(Procedure::Ed25519Sign {
            private_key: key,
            msg: msg.clone(),
        })
        .await
    {
        ProcResult::Ed25519Sign(ResultMessage::Ok(sig)) => sig,
        r => panic!("unexpected result: {:?}", r),
    };

    {
        use crypto::signatures::ed25519::{PublicKey, Signature};

        let pk = PublicKey::try_from_bytes(pk).unwrap();
        let sig = Signature::from_bytes(sig);
        assert!(pk.verify(&sig, &msg));
    }
}

#[actix::test]
async fn usecase_SLIP10Derive_intermediate_keys() {
    let (_cp, sh) = setup_stronghold().await;

    let seed = fresh::location();

    match sh
        .runtime_exec(Procedure::SLIP10Generate {
            size_bytes: None,
            output: seed.clone(),
            hint: fresh::record_hint(),
        })
        .await
    {
        ProcResult::SLIP10Generate(ResultMessage::OK) => (),
        r => panic!("unexpected result: {:?}", r),
    };

    let (_path, chain0) = fresh::hd_path();
    let (_path, chain1) = fresh::hd_path();

    let cc0 = match sh
        .runtime_exec(Procedure::SLIP10Derive {
            chain: chain0.join(&chain1),
            input: SLIP10DeriveInput::Seed(seed.clone()),
            output: fresh::location(),
            hint: fresh::record_hint(),
        })
        .await
    {
        ProcResult::SLIP10Derive(ResultMessage::Ok(cc)) => cc,
        r => panic!("unexpected result: {:?}", r),
    };

    let cc1 = {
        let intermediate = fresh::location();

        match sh
            .runtime_exec(Procedure::SLIP10Derive {
                chain: chain0,
                input: SLIP10DeriveInput::Seed(seed),
                output: intermediate.clone(),
                hint: fresh::record_hint(),
            })
            .await
        {
            ProcResult::SLIP10Derive(ResultMessage::Ok(_)) => (),
            r => panic!("unexpected result: {:?}", r),
        };

        match sh
            .runtime_exec(Procedure::SLIP10Derive {
                chain: chain1,
                input: SLIP10DeriveInput::Key(intermediate),
                output: fresh::location(),
                hint: fresh::record_hint(),
            })
            .await
        {
            ProcResult::SLIP10Derive(ResultMessage::Ok(cc)) => cc,
            r => panic!("unexpected result: {:?}", r),
        }
    };

    assert_eq!(cc0, cc1);
}

#[actix::test]
async fn usecase_sr25519() {
    let (_cp, sh) = setup_stronghold().await;

    let seed = fresh::location();

    match sh
        .runtime_exec(Procedure::Sr25519Generate {
            mnemonic_or_seed: if fresh::coinflip() {
                let mut entropy = [0u8; 32];
                fill(&mut entropy).unwrap();

                let mnemonic = bip39::wordlist::encode(&entropy, &bip39::wordlist::ENGLISH).unwrap();

                Some(mnemonic.to_string())
            } else {
                None
            },
            passphrase: if fresh::coinflip() {
                Some("password".into())
            } else {
                None
            },
            output: seed.clone(),
            hint: fresh::record_hint(),
        })
        .await
    {
        ProcResult::Sr25519Generate(ResultMessage::OK) => (),
        r => panic!("unexpected result: {:?}", r),
    }

    let chain = fresh::sr25519_chain();
    let key = fresh::location();

    match sh
        .runtime_exec(Procedure::Sr25519Derive {
            chain,
            input: seed.clone(),
            output: key.clone(),
            hint: fresh::record_hint(),
        })
        .await
    {
        ProcResult::Sr25519Derive(ResultMessage::OK) => (),
        r => panic!("unexpected result: {:?}", r),
    };

    for keypair in vec![key, seed] {
        let pk = match sh
            .runtime_exec(Procedure::Sr25519PublicKey {
                keypair: keypair.clone(),
            })
            .await
        {
            ProcResult::Sr25519PublicKey(ResultMessage::Ok(pk)) => pk,
            r => panic!("unexpected result: {:?}", r),
        };

        let msg = fresh::bytestring();

        let sig = match sh
            .runtime_exec(Procedure::Sr25519Sign {
                keypair,
                msg: msg.clone(),
            })
            .await
        {
            ProcResult::Sr25519Sign(ResultMessage::Ok(sig)) => sig,
            r => panic!("unexpected result: {:?}", r),
        };

        {
            assert!(pk.verify(&sig, &msg));
        }
    }
}

#[actix::test]
async fn usecase_secp256k1() {
    let (_cp, sh) = setup_stronghold().await;

    let seed = fresh::location();

    match sh
        .runtime_exec(Procedure::Secp256k1Generate {
            output: seed.clone(),
            hint: fresh::record_hint(),
        })
        .await
    {
        ProcResult::Secp256k1Generate(ResultMessage::OK) => (),
        r => panic!("unexpected result: {:?}", r),
    }

    let pk = match sh
        .runtime_exec(Procedure::Secp256k1PublicKey {
            private_key: seed.clone(),
        })
        .await
    {
        ProcResult::Secp256k1PublicKey(ResultMessage::Ok(pk)) => pk,
        r => panic!("unexpected result: {:?}", r),
    };

    let msg = rand::random();

    let (sig, recovery_id) = match sh
        .runtime_exec(Procedure::Secp256k1Sign {
            private_key: seed,
            msg: Box::new(msg),
        })
        .await
    {
        ProcResult::Secp256k1Sign(ResultMessage::Ok(sig)) => sig,
        r => panic!("unexpected result: {:?}", r),
    };

    {
        assert!(pk.verify(&msg, &sig));
        let p = crypto::signatures::secp256k1::PublicKey::recover(&msg, &sig, &recovery_id).unwrap();
        assert_eq!(pk, p);
    }
}
