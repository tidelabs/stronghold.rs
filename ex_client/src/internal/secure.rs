use crate::line_error;

use super::{LoadFromPath, Location, Provider, Store};

use engine::{
    store::Cache,
    vault::{ClientId, DbView, RecordId, VaultId},
};
use std::time::Duration;

#[derive(Clone)]
pub struct SecureBucket {
    pub db: DbView<Provider>,

    pub client_id: ClientId,

    pub store: Store,
}

impl SecureBucket {
    pub fn new(client_id: ClientId) -> Self {
        let store = Cache::new();

        Self {
            client_id,
            store,
            db: DbView::new(),
        }
    }

    pub fn write_to_store(&mut self, key: Vec<u8>, data: Vec<u8>, lifetime: Option<Duration>) -> Option<Vec<u8>> {
        self.store.insert(key, data, lifetime)
    }

    /// Attempts to read the data from the store.  Returns [`Some(Vec<u8>)`] if the key exists and [`None`] if it
    /// doesn't.
    pub fn read_from_store(&mut self, key: Vec<u8>) -> Option<Vec<u8>> {
        self.store.get(&key).map(|v| v.to_vec())
    }

    /// Deletes an item from the store by the given key.
    pub fn store_delete_item(&mut self, key: Vec<u8>) {
        self.store.remove(&key);
    }

    /// Checks to see if the key exists in the store.
    pub fn store_key_exists(&mut self, key: Vec<u8>) -> bool {
        self.store.contains_key(&key)
    }

    /// Sets the client id to swap from one client to another.
    pub fn set_client_id(&mut self, client_id: ClientId) {
        self.client_id = client_id
    }

    /// Rebuilds the cache using the parameters.
    pub fn rebuild_cache(&mut self, id: ClientId, store: Store) {
        self.client_id = id;
        self.store = store;
    }

    /// Gets the client string.
    pub fn get_client_str(&self) -> String {
        self.client_id.into()
    }
}

pub fn resolve_location<L: AsRef<Location>>(l: L) -> (VaultId, RecordId) {
    match l.as_ref() {
        Location::Generic {
            vault_path,
            record_path,
        } => {
            let vid = derive_vault_id(vault_path);
            let rid = RecordId::load_from_path(vid.as_ref(), record_path).expect(line_error!(""));
            (vid, rid)
        }
        Location::Counter { vault_path, counter } => {
            let vid = derive_vault_id(vault_path);
            let rid = derive_record_id(vault_path, *counter);

            (vid, rid)
        }
    }
}

/// Gets the [`VaultId`] from a specified path.
pub fn derive_vault_id<P: AsRef<Vec<u8>>>(path: P) -> VaultId {
    VaultId::load_from_path(path.as_ref(), path.as_ref()).expect(line_error!(""))
}

/// Derives the counter [`RecordId`] from the given vault path and the counter value.
pub fn derive_record_id<P: AsRef<Vec<u8>>>(vault_path: P, ctr: usize) -> RecordId {
    let vault_path = vault_path.as_ref();

    let path = if ctr == 0 {
        format!("{:?}{}", vault_path, "first_record")
    } else {
        format!("{:?}{}", vault_path, ctr)
    };

    RecordId::load_from_path(path.as_bytes(), path.as_bytes()).expect(line_error!())
}

// pub fn get_index_from_record_id<P: AsRef<Vec<u8>>>(vault_path: P, record_id: RecordId) -> usize {
//     let mut ctr = 0;
//     let vault_path = vault_path.as_ref();

//     while ctr <= 32_000_000 {
//         let rid = derive_record_id(vault_path, ctr);
//         if record_id == rid {
//             break;
//         }
//         ctr += 1;
//     }

//     ctr
// }
