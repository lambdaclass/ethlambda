use super::Table;

/// Storage error type.
pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// Result type for prefix iterator operations.
pub type PrefixResult = Result<(Box<[u8]>, Box<[u8]>), Error>;

/// A storage backend that can create read views and write batches.
pub trait StorageBackend {
    /// Begin a read-only transaction.
    fn begin_read(&self) -> Result<Box<dyn StorageReadView + '_>, Error>;

    /// Begin a write batch.
    fn begin_write(&self) -> Result<Box<dyn StorageWriteBatch + 'static>, Error>;
}

/// A read-only view of the storage.
pub trait StorageReadView {
    /// Get a value by key from a table.
    fn get(&self, table: Table, key: &[u8]) -> Result<Option<Vec<u8>>, Error>;

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

    /// Commit the batch, consuming it.
    fn commit(self: Box<Self>) -> Result<(), Error>;
}
