//! RocksDB storage backend.

use crate::api::{
    ALL_TABLES, Error, PrefixResult, StorageBackend, StorageReadView, StorageWriteBatch, Table,
};
use rocksdb::{
    ColumnFamilyDescriptor, DBWithThreadMode, MultiThreaded, Options, WriteBatch, WriteOptions,
};
use std::path::Path;
use std::sync::Arc;

/// Returns the column family name for a table.
fn cf_name(table: Table) -> &'static str {
    match table {
        Table::BlockHeaders => "block_headers",
        Table::BlockBodies => "block_bodies",
        Table::BlockSignatures => "block_signatures",
        Table::States => "states",
        Table::LatestKnownAttestations => "latest_known_attestations",
        Table::LatestNewAttestations => "latest_new_attestations",
        Table::GossipSignatures => "gossip_signatures",
        Table::AggregatedPayloads => "aggregated_payloads",
        Table::Metadata => "metadata",
        Table::LiveChain => "live_chain",
    }
}

/// RocksDB storage backend.
#[derive(Clone)]
pub struct RocksDBBackend {
    db: Arc<DBWithThreadMode<MultiThreaded>>,
}

impl RocksDBBackend {
    /// Open a RocksDB database at the given path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cf_descriptors: Vec<_> = ALL_TABLES
            .iter()
            .map(|t| ColumnFamilyDescriptor::new(cf_name(*t), Options::default()))
            .collect();

        let db =
            DBWithThreadMode::<MultiThreaded>::open_cf_descriptors(&opts, path, cf_descriptors)?;

        Ok(Self { db: Arc::new(db) })
    }
}

impl StorageBackend for RocksDBBackend {
    fn begin_read(&self) -> Result<Box<dyn StorageReadView + '_>, Error> {
        Ok(Box::new(RocksDBReadView {
            db: Arc::clone(&self.db),
        }))
    }

    fn begin_write(&self) -> Result<Box<dyn StorageWriteBatch + 'static>, Error> {
        Ok(Box::new(RocksDBWriteBatch {
            db: Arc::clone(&self.db),
            batch: WriteBatch::default(),
        }))
    }
}

/// Read-only view into RocksDB.
struct RocksDBReadView {
    db: Arc<DBWithThreadMode<MultiThreaded>>,
}

impl StorageReadView for RocksDBReadView {
    fn get(&self, table: Table, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let cf = self
            .db
            .cf_handle(cf_name(table))
            .ok_or_else(|| format!("Column family {} not found", cf_name(table)))?;

        Ok(self.db.get_cf(&cf, key)?)
    }

    fn prefix_iterator(
        &self,
        table: Table,
        prefix: &[u8],
    ) -> Result<Box<dyn Iterator<Item = PrefixResult> + '_>, Error> {
        let cf = self
            .db
            .cf_handle(cf_name(table))
            .ok_or_else(|| format!("Column family {} not found", cf_name(table)))?;

        let prefix_owned = prefix.to_vec();
        let iter = self
            .db
            .prefix_iterator_cf(&cf, prefix)
            .map(|result| result.map_err(|e| Box::new(e) as Error))
            .take_while(move |result| match result {
                Ok((key, _)) => key.starts_with(&prefix_owned),
                Err(_) => true, // propagate errors
            });

        Ok(Box::new(iter))
    }
}

/// Write batch for RocksDB.
struct RocksDBWriteBatch {
    db: Arc<DBWithThreadMode<MultiThreaded>>,
    batch: WriteBatch,
}

impl StorageWriteBatch for RocksDBWriteBatch {
    fn put_batch(&mut self, table: Table, batch: Vec<(Vec<u8>, Vec<u8>)>) -> Result<(), Error> {
        let cf = self
            .db
            .cf_handle(cf_name(table))
            .ok_or_else(|| format!("Column family {} not found", cf_name(table)))?;

        for (key, value) in batch {
            self.batch.put_cf(&cf, key, value);
        }
        Ok(())
    }

    fn delete_batch(&mut self, table: Table, keys: Vec<Vec<u8>>) -> Result<(), Error> {
        let cf = self
            .db
            .cf_handle(cf_name(table))
            .ok_or_else(|| format!("Column family {} not found", cf_name(table)))?;

        for key in keys {
            self.batch.delete_cf(&cf, key);
        }
        Ok(())
    }

    fn commit(self: Box<Self>) -> Result<(), Error> {
        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(false);

        self.db.write_opt(self.batch, &write_opts)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::Table;
    use crate::backend::tests::run_backend_tests;
    use tempfile::tempdir;

    #[test]
    fn test_rocksdb_backend() {
        let dir = tempdir().unwrap();
        let backend = RocksDBBackend::open(dir.path()).unwrap();
        run_backend_tests(&backend);
    }

    #[test]
    fn test_persistence() {
        let dir = tempdir().unwrap();

        // Write data
        {
            let backend = RocksDBBackend::open(dir.path()).unwrap();
            let mut batch = backend.begin_write().unwrap();
            batch
                .put_batch(Table::BlockHeaders, vec![(b"key1".to_vec(), b"value1".to_vec())])
                .unwrap();
            batch.commit().unwrap();
        }

        // Reopen and read
        {
            let backend = RocksDBBackend::open(dir.path()).unwrap();
            let view = backend.begin_read().unwrap();
            let value = view.get(Table::BlockHeaders, b"key1").unwrap();
            assert_eq!(value, Some(b"value1".to_vec()));
        }
    }
}
