use super::Table;

/// Storage error type.
pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// Result type for prefix iterator operations.
pub type PrefixResult = Result<(Box<[u8]>, Box<[u8]>), Error>;

/// A storage backend that can read and write data through views and batches.
pub trait StorageBackend: Send + Sync {
    /// Begin a read-only view.
    fn begin_read(&self) -> Result<Box<dyn StorageReadView + '_>, Error>;

    /// Begin a write batch.
    fn begin_write(&self) -> Result<Box<dyn StorageWriteBatch + 'static>, Error>;

    /// Estimated live data size in bytes for a table.
    /// Returns 0 if the backend does not support this (e.g. in-memory).
    fn estimate_table_bytes(&self, table: Table) -> u64 {
        let _ = table;
        0
    }
}

/// A read-only view of the storage.
pub trait StorageReadView {
    /// Calls `read_fn` with a borrow of the value stored under `key`, if any,
    /// and returns whether the key was present.
    ///
    /// The value is never copied: `read_fn` sees the backend's own buffer, so
    /// a caller that only decodes or inspects the bytes avoids allocating a
    /// value-sized `Vec` (full state snapshots are 100+ MB on mainnet-sized
    /// beacon chains). `read_fn` runs at most once, and its error is returned
    /// as-is. A `&mut dyn FnMut` rather than a generic closure, so the trait
    /// stays usable as `dyn StorageReadView`.
    fn read(
        &self,
        table: Table,
        key: &[u8],
        read_fn: &mut dyn FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<bool, Error>;

    /// Get a value by key from a table, copied into an owned `Vec`.
    fn get(&self, table: Table, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let mut value = None;
        self.read(table, key, &mut |bytes| {
            value = Some(bytes.to_vec());
            Ok(())
        })?;
        Ok(value)
    }

    /// Whether `key` is present in a table.
    ///
    /// Same answer as `get(..)?.is_some()` but never materializes the value, so
    /// the cost does not scale with its size. Prefer it for pure existence
    /// checks on large values.
    fn contains(&self, table: Table, key: &[u8]) -> Result<bool, Error> {
        self.read(table, key, &mut |_| Ok(()))
    }

    /// Iterate over all entries with a given key prefix.
    fn prefix_iterator(
        &self,
        table: Table,
        prefix: &[u8],
    ) -> Result<Box<dyn Iterator<Item = PrefixResult> + '_>, Error>;
}

/// A write batch that can be committed atomically.
pub trait StorageWriteBatch: Send {
    /// Put multiple key-value pairs into a table.
    fn put_batch(&mut self, table: Table, batch: Vec<(Vec<u8>, Vec<u8>)>) -> Result<(), Error>;

    /// Delete multiple keys from a table.
    fn delete_batch(&mut self, table: Table, keys: Vec<Vec<u8>>) -> Result<(), Error>;

    /// Delete every key in the half-open range `[from, to)` from a table.
    ///
    /// Unlike [`delete_batch`](Self::delete_batch), the caller does not need to
    /// know the keys, so the write cost need not scale with the number of
    /// entries covered: RocksDB records a single range tombstone instead of one
    /// delete per key. Operations within a batch apply in call order, so a later
    /// `put_batch` for a key inside the range still wins.
    fn delete_range(&mut self, table: Table, from: &[u8], to: &[u8]) -> Result<(), Error>;

    /// Commit the batch, consuming it.
    fn commit(self: Box<Self>) -> Result<(), Error>;
}
