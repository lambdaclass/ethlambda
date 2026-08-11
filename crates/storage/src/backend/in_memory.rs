use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::api::{
    ALL_TABLES, Error, PrefixResult, StorageBackend, StorageReadView, StorageWriteBatch, Table,
};

type TableData = HashMap<Vec<u8>, Vec<u8>>;
type StorageData = HashMap<Table, TableData>;

/// Pending operation in a batch, replayed in call order on commit so the last
/// operation touching a key wins (matching how RocksDB applies a `WriteBatch`).
enum PendingOp {
    Put(Vec<u8>, Vec<u8>),
    Delete(Vec<u8>),
    /// Delete every key in the half-open range `[from, to)`.
    DeleteRange(Vec<u8>, Vec<u8>),
}

type PendingOps = Vec<(Table, PendingOp)>;

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
            ops: PendingOps::new(),
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

        // Collect and sort by key so iteration order matches the RocksDB backend
        // (lexicographic). Callers rely on this for early-stop range scans over
        // slot||root keys (e.g. signature/live-chain pruning).
        let mut items: Vec<(Vec<u8>, Vec<u8>)> = table_data
            .iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        items.sort_by(|a, b| a.0.cmp(&b.0));

        let iter = items
            .into_iter()
            .map(|(k, v)| Ok((k.into_boxed_slice(), v.into_boxed_slice())));

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
        for (key, value) in batch {
            self.ops.push((table, PendingOp::Put(key, value)));
        }
        Ok(())
    }

    fn delete_batch(&mut self, table: Table, keys: Vec<Vec<u8>>) -> Result<(), Error> {
        for key in keys {
            self.ops.push((table, PendingOp::Delete(key)));
        }
        Ok(())
    }

    fn delete_range(&mut self, table: Table, from: &[u8], to: &[u8]) -> Result<(), Error> {
        let range = PendingOp::DeleteRange(from.to_vec(), to.to_vec());
        self.ops.push((table, range));
        Ok(())
    }

    fn commit(self: Box<Self>) -> Result<(), Error> {
        let mut guard = self.data.write().map_err(|e| e.to_string())?;

        for (table, op) in self.ops {
            let table_data = guard.get_mut(&table).expect("table exists");
            match op {
                PendingOp::Put(key, value) => {
                    table_data.insert(key, value);
                }
                PendingOp::Delete(key) => {
                    table_data.remove(&key);
                }
                // Keys are unordered here, so the range is applied by scanning
                // the table rather than by seeking to `from`.
                PendingOp::DeleteRange(from, to) => {
                    table_data.retain(|key, _| key < &from || key >= &to);
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
