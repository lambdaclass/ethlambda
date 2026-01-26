use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::api::{
    ALL_TABLES, Error, PrefixResult, StorageBackend, StorageReadView, StorageWriteBatch, Table,
};

type TableData = HashMap<Vec<u8>, Vec<u8>>;
type StorageData = HashMap<Table, TableData>;

/// Pending operation for a key - last operation wins.
enum PendingOp {
    Put(Vec<u8>),
    Delete,
}

type PendingOps = HashMap<Table, HashMap<Vec<u8>, PendingOp>>;

/// In-memory storage backend using HashMaps.
///
/// All tables are created (empty) on initialization.
#[derive(Clone)]
pub struct InMemoryBackend {
    data: Arc<RwLock<StorageData>>,
}

impl Default for InMemoryBackend {
    fn default() -> Self {
        let mut data = StorageData::new();
        for table in ALL_TABLES {
            data.insert(table, TableData::new());
        }
        Self {
            data: Arc::new(RwLock::new(data)),
        }
    }
}

impl InMemoryBackend {
    /// Create a new in-memory backend with all tables initialized empty.
    pub fn new() -> Self {
        Self::default()
    }
}

impl StorageBackend for InMemoryBackend {
    fn begin_read(&self) -> Result<Box<dyn StorageReadView + '_>, Error> {
        let guard = self.data.read().map_err(|e| e.to_string())?;
        Ok(Box::new(InMemoryReadView { guard }))
    }

    fn begin_write(&self) -> Result<Box<dyn StorageWriteBatch + 'static>, Error> {
        Ok(Box::new(InMemoryWriteBatch {
            data: Arc::clone(&self.data),
            ops: HashMap::new(),
        }))
    }
}

/// Read view holding a read lock on the storage data.
struct InMemoryReadView<'a> {
    guard: std::sync::RwLockReadGuard<'a, StorageData>,
}

impl StorageReadView for InMemoryReadView<'_> {
    fn get(&self, table: Table, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        Ok(self
            .guard
            .get(&table)
            .expect("table exists")
            .get(key)
            .cloned())
    }

    fn prefix_iterator(
        &self,
        table: Table,
        prefix: &[u8],
    ) -> Result<Box<dyn Iterator<Item = PrefixResult> + '_>, Error> {
        let table_data = self.guard.get(&table).expect("table exists");
        let prefix_owned = prefix.to_vec();

        let iter = table_data
            .iter()
            .filter(move |(k, _)| k.starts_with(&prefix_owned))
            .map(|(k, v)| Ok((k.clone().into_boxed_slice(), v.clone().into_boxed_slice())));

        Ok(Box::new(iter))
    }
}

/// Write batch that accumulates changes before committing.
struct InMemoryWriteBatch {
    data: Arc<RwLock<StorageData>>,
    ops: PendingOps,
}

impl StorageWriteBatch for InMemoryWriteBatch {
    fn put_batch(&mut self, table: Table, batch: Vec<(Vec<u8>, Vec<u8>)>) -> Result<(), Error> {
        let table_ops = self.ops.entry(table).or_default();
        for (key, value) in batch {
            table_ops.insert(key, PendingOp::Put(value));
        }
        Ok(())
    }

    fn delete_batch(&mut self, table: Table, keys: Vec<Vec<u8>>) -> Result<(), Error> {
        let table_ops = self.ops.entry(table).or_default();
        for key in keys {
            table_ops.insert(key, PendingOp::Delete);
        }
        Ok(())
    }

    fn commit(self: Box<Self>) -> Result<(), Error> {
        let mut guard = self.data.write().map_err(|e| e.to_string())?;

        for (table, ops) in self.ops {
            let table_data = guard.get_mut(&table).expect("table exists");
            for (key, op) in ops {
                match op {
                    PendingOp::Put(value) => {
                        table_data.insert(key, value);
                    }
                    PendingOp::Delete => {
                        table_data.remove(&key);
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::tests::run_backend_tests;

    #[test]
    fn test_in_memory_backend() {
        let backend = InMemoryBackend::new();
        run_backend_tests(&backend);
    }
}
