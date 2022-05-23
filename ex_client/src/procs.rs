use crate::{resolve_location, KeyStore, Location, RecordHint, SecureBucket};

use crypto::keys::bip39;
use crypto::signatures::sr25519::{KeyPair as Sr25519KeyPair, Signature};
use crypto::utils::rand;

pub fn sr25519_generate_seed(
    mut bucket: SecureBucket,
    mut keystore: KeyStore,
    mnemonic_or_seed: Option<String>,
    passphrase: Option<String>,
    output: Location,
) -> crate::Result<()> {
    let (vid, rid) = resolve_location(output);
    let hint = RecordHint::new(b"seed").map_err(|_| crate::Error::CryptoError("Failed to generate hint".into()))?;

    let passphrase = if let Some(pass) = passphrase {
        pass
    } else {
        String::from("")
    };

    let keypair = if let Some(mnemonic) = mnemonic_or_seed {
        Sr25519KeyPair::from_string(&mnemonic, Some(&passphrase))
            .map_err(|_| crate::Error::CryptoError("Couldn't create keypair".into()))?
    } else {
        let mut entropy = [0u8; 32];
        rand::fill(&mut entropy).map_err(|_| crate::Error::CryptoError("Failed to generate entropy".into()))?;

        let mnemonic = bip39::wordlist::encode(&entropy, &bip39::wordlist::ENGLISH)
            .map_err(|_| crate::Error::CryptoError("Failed to call bip39".into()))?;

        Sr25519KeyPair::from_string(&mnemonic, Some(&passphrase))
            .map_err(|_| crate::Error::CryptoError("Couldn't create keypair".into()))?
    };

    if !keystore.vault_exists(vid) {
        keystore.create_key(vid);
    }

    let key = keystore
        .take_key(vid)
        .map_err(|_| crate::Error::KeyStoreError("Failed to take key".into()))?;

    keystore.insert_key(vid, key.clone());

    bucket.db.write(&key, vid, rid, &keypair.seed(), hint)?;

    Ok(())
}

pub fn sr25519_sign_inner(
    mut bucket: SecureBucket,
    mut keystore: KeyStore,
    msg: Vec<u8>,
    loc: Location,
) -> crate::Result<Signature> {
    let (vid, rid) = resolve_location(loc);
    let key = keystore
        .take_key(vid)
        .map_err(|_e| crate::Error::KeyStoreError("Failed to take key".into()))?;

    let mut res: [u8; 64] = [0u8; 64];

    bucket.db.get_guard(&key, vid, rid, |guard| {
        let raw = guard.borrow();

        if raw.len() != 64 {
            return Err(engine::Error::DatabaseError(
                "incorrect number of private key bytes".into(),
            ));
        }

        let keypair = Sr25519KeyPair::from_seed(&raw);
        let sig = keypair.sign(&msg);

        res.copy_from_slice(sig.as_ref());

        Ok(())
    })?;

    Signature::from_slice(&res).map_err(|_| crate::Error::SignatureError)
}

pub fn public_key_inner(mut bucket: SecureBucket, mut keystore: KeyStore, loc: Location) -> crate::Result<[u8; 32]> {
    let (vid, rid) = resolve_location(loc);
    let key = keystore
        .take_key(vid)
        .map_err(|_e| crate::Error::KeyStoreError("Failed to take key".into()))?;

    let mut res: [u8; 32] = [0u8; 32];

    bucket.db.get_guard(&key, vid, rid, |guard| {
        let raw = guard.borrow();

        if raw.len() != 64 {
            return Err(engine::Error::DatabaseError(
                "incorrect number of private key bytes".into(),
            ));
        }

        let keypair = Sr25519KeyPair::from_seed(&raw);
        let pk = keypair.public_key();
        let pk = pk.inner();

        res.copy_from_slice(pk.as_ref());

        Ok(())
    })?;

    Ok(res)
}
