#![allow(dead_code)] // Infrastructure not yet integrated with Store

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::api::{Error, PrefixResult, StorageBackend, StorageReadView, StorageWriteBatch, Table};

type TableData = HashMap<Vec<u8>, Vec<u8>>;
type StorageData = HashMap<Table, TableData>;
type PendingEntries = HashMap<Table, Vec<(Vec<u8>, Vec<u8>)>>;
type PendingDeletes = HashMap<Table, Vec<Vec<u8>>>;

/// In-memory storage backend using HashMaps.
#[derive(Clone, Default)]
pub struct InMemoryBackend {
    data: Arc<RwLock<StorageData>>,
}

impl InMemoryBackend {
    /// Create a new empty in-memory backend.
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
            pending: HashMap::new(),
            deletes: HashMap::new(),
        }))
    }
}

/// Read view holding a read lock on the storage data.
struct InMemoryReadView<'a> {
    guard: std::sync::RwLockReadGuard<'a, StorageData>,
}

impl StorageReadView for InMemoryReadView<'_> {
    fn get(&self, table: Table, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.guard.get(&table).and_then(|t| t.get(key)).cloned())
    }

    fn prefix_iterator(
        &self,
        table: Table,
        prefix: &[u8],
    ) -> Result<Box<dyn Iterator<Item = PrefixResult> + '_>, Error> {
        let table_data = self.guard.get(&table);
        let prefix_owned = prefix.to_vec();

        let iter: Box<dyn Iterator<Item = PrefixResult> + '_> = match table_data {
            Some(data) => Box::new(
                data.iter()
                    .filter(move |(k, _)| k.starts_with(&prefix_owned))
                    .map(|(k, v)| Ok((k.clone().into_boxed_slice(), v.clone().into_boxed_slice()))),
            ),
            None => Box::new(std::iter::empty()),
        };

        Ok(iter)
    }
}

/// Write batch that accumulates changes before committing.
struct InMemoryWriteBatch {
    data: Arc<RwLock<StorageData>>,
    pending: PendingEntries,
    deletes: PendingDeletes,
}

impl StorageWriteBatch for InMemoryWriteBatch {
    fn put_batch(&mut self, table: Table, batch: Vec<(Vec<u8>, Vec<u8>)>) -> Result<(), Error> {
        self.pending.entry(table).or_default().extend(batch);
        Ok(())
    }

    fn delete_batch(&mut self, table: Table, keys: Vec<Vec<u8>>) -> Result<(), Error> {
        self.deletes.entry(table).or_default().extend(keys);
        Ok(())
    }

    fn commit(self: Box<Self>) -> Result<(), Error> {
        let mut guard = self.data.write().map_err(|e| e.to_string())?;

        // Apply puts
        for (table, entries) in self.pending {
            let table_data = guard.entry(table).or_default();
            for (key, value) in entries {
                table_data.insert(key, value);
            }
        }

        // Apply deletes
        for (table, keys) in self.deletes {
            if let Some(table_data) = guard.get_mut(&table) {
                for key in keys {
                    table_data.remove(&key);
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_put_and_get() {
        let backend = InMemoryBackend::new();

        // Write data
        {
            let mut batch = backend.begin_write().unwrap();
            batch
                .put_batch(Table::Blocks, vec![(b"key1".to_vec(), b"value1".to_vec())])
                .unwrap();
            batch.commit().unwrap();
        }

        // Read data
        {
            let view = backend.begin_read().unwrap();
            let value = view.get(Table::Blocks, b"key1").unwrap();
            assert_eq!(value, Some(b"value1".to_vec()));
        }
    }

    #[test]
    fn test_delete() {
        let backend = InMemoryBackend::new();

        // Write data
        {
            let mut batch = backend.begin_write().unwrap();
            batch
                .put_batch(Table::Blocks, vec![(b"key1".to_vec(), b"value1".to_vec())])
                .unwrap();
            batch.commit().unwrap();
        }

        // Delete data
        {
            let mut batch = backend.begin_write().unwrap();
            batch
                .delete_batch(Table::Blocks, vec![b"key1".to_vec()])
                .unwrap();
            batch.commit().unwrap();
        }

        // Verify deleted
        {
            let view = backend.begin_read().unwrap();
            let value = view.get(Table::Blocks, b"key1").unwrap();
            assert_eq!(value, None);
        }
    }

    #[test]
    fn test_prefix_iterator() {
        let backend = InMemoryBackend::new();

        // Write data with common prefix
        {
            let mut batch = backend.begin_write().unwrap();
            batch
                .put_batch(
                    Table::Metadata,
                    vec![
                        (b"config:a".to_vec(), b"1".to_vec()),
                        (b"config:b".to_vec(), b"2".to_vec()),
                        (b"other:x".to_vec(), b"3".to_vec()),
                    ],
                )
                .unwrap();
            batch.commit().unwrap();
        }

        // Query by prefix
        {
            let view = backend.begin_read().unwrap();
            let mut results: Vec<_> = view
                .prefix_iterator(Table::Metadata, b"config:")
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();

            results.sort_by(|a, b| a.0.cmp(&b.0));
            assert_eq!(results.len(), 2);
            assert_eq!(&*results[0].0, b"config:a");
            assert_eq!(&*results[1].0, b"config:b");
        }
    }

    #[test]
    fn test_nonexistent_key() {
        let backend = InMemoryBackend::new();
        let view = backend.begin_read().unwrap();
        let value = view.get(Table::Blocks, b"nonexistent").unwrap();
        assert_eq!(value, None);
    }

    #[test]
    fn test_multiple_tables() {
        let backend = InMemoryBackend::new();

        // Write to different tables
        {
            let mut batch = backend.begin_write().unwrap();
            batch
                .put_batch(Table::Blocks, vec![(b"key".to_vec(), b"block".to_vec())])
                .unwrap();
            batch
                .put_batch(Table::States, vec![(b"key".to_vec(), b"state".to_vec())])
                .unwrap();
            batch.commit().unwrap();
        }

        // Verify isolation
        {
            let view = backend.begin_read().unwrap();
            assert_eq!(
                view.get(Table::Blocks, b"key").unwrap(),
                Some(b"block".to_vec())
            );
            assert_eq!(
                view.get(Table::States, b"key").unwrap(),
                Some(b"state".to_vec())
            );
        }
    }
}
