//! Shared tests for storage backends.
//!
//! This module provides a generic test suite that can be run against any
//! `StorageBackend` implementation to verify correct behavior.
//!
//! Note: These tests use simple text keys (e.g., `b"test_put_get_key"`) rather
//! than real production data (SSZ-encoded H256 hashes, validator indices, etc.).
//! This may cause issues if a backend implementation relies on specific key
//! formats or lengths. If adding a backend with such constraints, consider
//! adding backend-specific tests with realistic data.

use crate::api::{StorageBackend, Table};

/// Run the full test suite against a backend.
pub fn run_backend_tests(backend: &dyn StorageBackend) {
    test_put_and_get(backend);
    test_delete(backend);
    test_prefix_iterator(backend);
    test_nonexistent_key(backend);
    test_delete_then_put(backend);
    test_put_then_delete(backend);
    test_multiple_tables(backend);
}

fn test_put_and_get(backend: &dyn StorageBackend) {
    // Write data
    {
        let mut batch = backend.begin_write().unwrap();
        batch
            .put_batch(
                Table::Blocks,
                vec![(b"test_put_get_key".to_vec(), b"value1".to_vec())],
            )
            .unwrap();
        batch.commit().unwrap();
    }

    // Read data
    {
        let view = backend.begin_read().unwrap();
        let value = view.get(Table::Blocks, b"test_put_get_key").unwrap();
        assert_eq!(value, Some(b"value1".to_vec()));
    }
}

fn test_delete(backend: &dyn StorageBackend) {
    // Write data
    {
        let mut batch = backend.begin_write().unwrap();
        batch
            .put_batch(
                Table::Blocks,
                vec![(b"test_delete_key".to_vec(), b"value1".to_vec())],
            )
            .unwrap();
        batch.commit().unwrap();
    }

    // Delete data
    {
        let mut batch = backend.begin_write().unwrap();
        batch
            .delete_batch(Table::Blocks, vec![b"test_delete_key".to_vec()])
            .unwrap();
        batch.commit().unwrap();
    }

    // Verify deleted
    {
        let view = backend.begin_read().unwrap();
        let value = view.get(Table::Blocks, b"test_delete_key").unwrap();
        assert_eq!(value, None);
    }
}

fn test_prefix_iterator(backend: &dyn StorageBackend) {
    // Write data with common prefix
    {
        let mut batch = backend.begin_write().unwrap();
        batch
            .put_batch(
                Table::Metadata,
                vec![
                    (b"test_prefix:a".to_vec(), b"1".to_vec()),
                    (b"test_prefix:b".to_vec(), b"2".to_vec()),
                    (b"test_other:x".to_vec(), b"3".to_vec()),
                ],
            )
            .unwrap();
        batch.commit().unwrap();
    }

    // Query by prefix
    {
        let view = backend.begin_read().unwrap();
        let mut results: Vec<_> = view
            .prefix_iterator(Table::Metadata, b"test_prefix:")
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        results.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(results.len(), 2);
        assert_eq!(&*results[0].0, b"test_prefix:a");
        assert_eq!(&*results[1].0, b"test_prefix:b");
    }
}

fn test_nonexistent_key(backend: &dyn StorageBackend) {
    let view = backend.begin_read().unwrap();
    let value = view
        .get(Table::Blocks, b"test_nonexistent_key_12345")
        .unwrap();
    assert_eq!(value, None);
}

fn test_delete_then_put(backend: &dyn StorageBackend) {
    // Initial value
    {
        let mut batch = backend.begin_write().unwrap();
        batch
            .put_batch(
                Table::Blocks,
                vec![(b"test_del_put_key".to_vec(), b"old".to_vec())],
            )
            .unwrap();
        batch.commit().unwrap();
    }

    // Delete then put in same batch - put should win
    {
        let mut batch = backend.begin_write().unwrap();
        batch
            .delete_batch(Table::Blocks, vec![b"test_del_put_key".to_vec()])
            .unwrap();
        batch
            .put_batch(
                Table::Blocks,
                vec![(b"test_del_put_key".to_vec(), b"new".to_vec())],
            )
            .unwrap();
        batch.commit().unwrap();
    }

    let view = backend.begin_read().unwrap();
    assert_eq!(
        view.get(Table::Blocks, b"test_del_put_key").unwrap(),
        Some(b"new".to_vec())
    );
}

fn test_put_then_delete(backend: &dyn StorageBackend) {
    // Put then delete in same batch - delete should win
    {
        let mut batch = backend.begin_write().unwrap();
        batch
            .put_batch(
                Table::Blocks,
                vec![(b"test_put_del_key".to_vec(), b"value".to_vec())],
            )
            .unwrap();
        batch
            .delete_batch(Table::Blocks, vec![b"test_put_del_key".to_vec()])
            .unwrap();
        batch.commit().unwrap();
    }

    let view = backend.begin_read().unwrap();
    assert_eq!(view.get(Table::Blocks, b"test_put_del_key").unwrap(), None);
}

fn test_multiple_tables(backend: &dyn StorageBackend) {
    // Write to different tables
    {
        let mut batch = backend.begin_write().unwrap();
        batch
            .put_batch(
                Table::Blocks,
                vec![(b"test_multi_key".to_vec(), b"block".to_vec())],
            )
            .unwrap();
        batch
            .put_batch(
                Table::States,
                vec![(b"test_multi_key".to_vec(), b"state".to_vec())],
            )
            .unwrap();
        batch.commit().unwrap();
    }

    // Verify isolation
    {
        let view = backend.begin_read().unwrap();
        assert_eq!(
            view.get(Table::Blocks, b"test_multi_key").unwrap(),
            Some(b"block".to_vec())
        );
        assert_eq!(
            view.get(Table::States, b"test_multi_key").unwrap(),
            Some(b"state".to_vec())
        );
    }
}
