use crate::{resolve_location, KeyStore, Location, SecureBucket};

use subxt::sp_core::sr25519::Signature;

use crypto::signatures::sr25519::KeyPair as Sr25519KeyPair;

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

    Ok(Signature::from_slice(&res))
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
