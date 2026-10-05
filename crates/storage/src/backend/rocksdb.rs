//! RocksDB storage backend.

use crate::api::{
    ALL_TABLES, Error, PrefixResult, StorageBackend, StorageReadView, StorageWriteBatch, Table,
};
use rocksdb::{
    BlockBasedOptions, Cache, ColumnFamilyDescriptor, DBCompressionType, DBWithThreadMode,
    MultiThreaded, Options, WriteBatch, WriteOptions,
};
use std::path::Path;
use std::sync::Arc;

/// Returns the column family name for a table.
///
/// Delegates to [`Table::name`] so the CF name and the metrics label share a
/// single source of truth (and a new table only needs one mapping).
fn cf_name(table: Table) -> &'static str {
    table.name()
}

/// The smallest value a blob-file table stores out of line.
///
/// RocksDB's default data block size: a larger value would get an oversized
/// block of its own anyway, so it gains nothing from staying inline.
const MIN_BLOB_SIZE: u64 = 4 * 1024;

/// Whether a table keeps its values in blob files rather than inline in SSTs.
///
/// `States` holds full state snapshots (100+ MB on mainnet-sized beacon
/// chains) and `StateDiffs` the deltas between them (hundreds of KB). Inline,
/// every compaction that touches a file rewrites those values, and a lookup
/// that misses still reads the data block around the key, which here can be
/// a whole snapshot. In a blob file a value is written once, and the SSTs
/// hold only small references to it.
fn stores_values_in_blob_files(table: Table) -> bool {
    matches!(table, Table::States | Table::StateDiffs)
}

/// Moves a column family's large values into blob files.
///
/// RocksDB applies the change to an existing database as it goes: new
/// writes land in blob files, and inline values move out as compaction
/// rewrites their SSTs. So a data directory written without it opens
/// unchanged, and no `DB_VERSION` bump is needed.
fn enable_blob_files(cf_opts: &mut Options) {
    cf_opts.set_enable_blob_files(true);
    cf_opts.set_min_blob_size(MIN_BLOB_SIZE);
    // SST blocks get RocksDB's default Snappy, but blob files default to no
    // compression, so moving the values out would otherwise grow the tables
    // on disk. The values are raw SSZ.
    cf_opts.set_blob_compression_type(DBCompressionType::Lz4);
    // No blob garbage collection: nothing deletes or overwrites a state, so it
    // would only relocate live blobs during compaction. Revisit if states are
    // ever pruned. No blob cache either: the store caches decoded states
    // itself, and a snapshot-sized entry would evict the whole block cache.
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

        opts.set_max_open_files(-1);
        opts.set_max_file_opening_threads(8);
        opts.set_max_background_jobs(8);
        opts.set_max_subcompactions(2);
        opts.set_compaction_readahead_size(4 * 1024 * 1024);
        opts.set_level_compaction_dynamic_level_bytes(true);
        opts.set_bytes_per_sync(32 * 1024 * 1024);
        opts.set_wal_bytes_per_sync(32 * 1024 * 1024);
        opts.set_max_total_wal_size(256 * 1024 * 1024);
        opts.set_use_fsync(false);
        opts.set_enable_pipelined_write(true);

        let block_cache = Cache::new_lru_cache(128 * 1024 * 1024);
        let mut block_opts = BlockBasedOptions::default();
        block_opts.set_block_cache(&block_cache);

        let cf_descriptors: Vec<_> = ALL_TABLES
            .iter()
            .map(|t| {
                let mut cf_opts = Options::default();
                cf_opts.set_block_based_table_factory(&block_opts);
                if stores_values_in_blob_files(*t) {
                    enable_blob_files(&mut cf_opts);
                }
                ColumnFamilyDescriptor::new(cf_name(*t), cf_opts)
            })
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

    fn estimate_table_bytes(&self, table: Table) -> u64 {
        let Some(cf) = self.db.cf_handle(cf_name(table)) else {
            return 0;
        };
        let sst_bytes = self
            .db
            .property_int_value_cf(&cf, "rocksdb.estimate-live-data-size")
            .ok()
            .flatten()
            .unwrap_or(0);
        let memtable_bytes = self
            .db
            .property_int_value_cf(&cf, "rocksdb.cur-size-all-mem-tables")
            .ok()
            .flatten()
            .unwrap_or(0);
        // `estimate-live-data-size` counts SST files only, so a blob-file
        // table's values would otherwise vanish from the estimate.
        let blob_bytes = self
            .db
            .property_int_value_cf(&cf, "rocksdb.live-blob-file-size")
            .ok()
            .flatten()
            .unwrap_or(0);
        sst_bytes + memtable_bytes + blob_bytes
    }
}

/// Read-only view into RocksDB.
struct RocksDBReadView {
    db: Arc<DBWithThreadMode<MultiThreaded>>,
}

impl StorageReadView for RocksDBReadView {
    fn read(
        &self,
        table: Table,
        key: &[u8],
        read_fn: &mut dyn FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<bool, Error> {
        let cf = self
            .db
            .cf_handle(cf_name(table))
            .ok_or_else(|| format!("Column family {} not found", cf_name(table)))?;

        // Pinned: references RocksDB's own buffer instead of copying the
        // value into a `Vec`.
        let Some(value) = self.db.get_pinned_cf(&cf, key)? else {
            return Ok(false);
        };
        read_fn(&value)?;
        Ok(true)
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

    fn delete_range(&mut self, table: Table, from: &[u8], to: &[u8]) -> Result<(), Error> {
        let cf = self
            .db
            .cf_handle(cf_name(table))
            .ok_or_else(|| format!("Column family {} not found", cf_name(table)))?;

        self.batch.delete_range_cf(&cf, from, to);
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

    /// A value big enough for a blob file, and the property counting them.
    const BLOB_VALUE_LEN: usize = 64 * 1024;
    const NUM_BLOB_FILES: &str = "rocksdb.num-blob-files";

    fn num_blob_files(backend: &RocksDBBackend, table: Table) -> u64 {
        let cf = backend.db.cf_handle(cf_name(table)).unwrap();
        backend
            .db
            .property_int_value_cf(&cf, NUM_BLOB_FILES)
            .unwrap()
            .unwrap()
    }

    fn put_and_flush(backend: &RocksDBBackend, table: Table, key: &[u8], value: Vec<u8>) {
        let mut batch = backend.begin_write().unwrap();
        batch.put_batch(table, vec![(key.to_vec(), value)]).unwrap();
        batch.commit().unwrap();
        let cf = backend.db.cf_handle(cf_name(table)).unwrap();
        backend.db.flush_cf(&cf).unwrap();
    }

    #[test]
    fn large_state_values_live_in_blob_files() {
        let dir = tempdir().unwrap();
        let backend = RocksDBBackend::open(dir.path()).unwrap();
        let value: Vec<u8> = (0..BLOB_VALUE_LEN).map(|i| (i % 251) as u8).collect();

        for table in [Table::States, Table::StateDiffs] {
            put_and_flush(&backend, table, b"big", value.clone());
            assert_eq!(num_blob_files(&backend, table), 1, "{table:?}");

            let view = backend.begin_read().unwrap();
            assert_eq!(view.get(table, b"big").unwrap(), Some(value.clone()));
            assert!(view.contains(table, b"big").unwrap());
            assert!(!view.contains(table, b"absent").unwrap());
        }
        assert!(backend.estimate_table_bytes(Table::States) > 0);

        // Small values, and every other table, stay inline.
        put_and_flush(&backend, Table::States, b"small", vec![7; 16]);
        assert_eq!(num_blob_files(&backend, Table::States), 1);
        put_and_flush(&backend, Table::BlockHeaders, b"big", value);
        assert_eq!(num_blob_files(&backend, Table::BlockHeaders), 0);
    }

    #[test]
    fn a_directory_written_without_blob_files_still_reads() {
        let dir = tempdir().unwrap();
        let value: Vec<u8> = (0..BLOB_VALUE_LEN).map(|i| (i % 251) as u8).collect();

        // The layout a data directory had before blob files: every table
        // with plain options.
        {
            let mut opts = Options::default();
            opts.create_if_missing(true);
            opts.create_missing_column_families(true);
            let cfs = ALL_TABLES.iter().map(|t| cf_name(*t));
            let db = DBWithThreadMode::<MultiThreaded>::open_cf(&opts, dir.path(), cfs).unwrap();
            let cf = db.cf_handle(cf_name(Table::States)).unwrap();
            db.put_cf(&cf, b"old", &value).unwrap();
            db.flush_cf(&cf).unwrap();
        }

        let backend = RocksDBBackend::open(dir.path()).unwrap();
        assert_eq!(num_blob_files(&backend, Table::States), 0);
        put_and_flush(&backend, Table::States, b"new", value.clone());
        assert_eq!(num_blob_files(&backend, Table::States), 1);

        let view = backend.begin_read().unwrap();
        assert_eq!(
            view.get(Table::States, b"old").unwrap(),
            Some(value.clone())
        );
        assert_eq!(view.get(Table::States, b"new").unwrap(), Some(value));
    }

    #[test]
    fn test_persistence() {
        let dir = tempdir().unwrap();

        // Write data
        {
            let backend = RocksDBBackend::open(dir.path()).unwrap();
            let mut batch = backend.begin_write().unwrap();
            batch
                .put_batch(
                    Table::BlockHeaders,
                    vec![(b"key1".to_vec(), b"value1".to_vec())],
                )
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
