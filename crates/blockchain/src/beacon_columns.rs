//! The chain actor's parking lot for data column sidecars the p2p layer's
//! checks could not judge yet.
//!
//! A sidecar is judged against a block's post-state: its parent's for a fulu
//! sidecar, its own block's for a gloas one. Until that state exists the
//! sidecar's bytes wait in `Table::PendingDataColumns`, and only their keys are
//! held in `BlockChainServer::sidecars_awaiting_parent`.

use std::collections::HashSet;

use ethlambda_types::ShortRoot;
use ethlambda_types::beacon::containers::DataColumnSidecar;
use ethlambda_types::primitives::H256;
use tracing::{debug, error, info, trace};

use crate::{BlockChainServer, metrics};

/// Where a parked data column sidecar was put.
///
/// The three fields are exactly `Table::PendingDataColumns`'s key, so reading
/// the sidecar back needs nothing else. `slot` is also what the finality sweep
/// compares against.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ParkedColumn {
    pub(crate) slot: u64,
    pub(crate) block_root: H256,
    pub(crate) index: u64,
}

/// The root whose post-state `sidecar` cannot be checked without.
///
/// A fulu sidecar is verified against its parent's state (its proposer and
/// signature live there). A gloas sidecar carries neither, but reads its
/// commitments from its own block's bid, so it waits for that block instead.
pub(crate) fn awaited_root(sidecar: &DataColumnSidecar) -> H256 {
    match sidecar {
        DataColumnSidecar::Fulu(sidecar) => sidecar.signed_block_header.message.parent_root,
        DataColumnSidecar::Gloas(sidecar) => sidecar.beacon_block_root,
    }
}

impl BlockChainServer {
    /// Park sidecars the chain checks found no parent post-state for, or send
    /// them straight back to be checked if the parent has one by now.
    ///
    /// The second case is a race this actor has to close, because the checks
    /// run elsewhere: the p2p layer looked for the parent's post-state, found
    /// none and sent these, and if the parent imported in between, its
    /// [`Self::drain_sidecars_awaiting_parent`] has already run and will not
    /// run again, so a sidecar parked now would wait for nothing until
    /// finality evicts it. Asked with the same `get_state` the checks use, so
    /// a sidecar sent back is one they will find a parent state for.
    pub(crate) fn park_data_columns(&mut self, sidecars: Vec<DataColumnSidecar>) {
        let mut ready = Vec::new();
        for sidecar in sidecars {
            let awaited = awaited_root(&sidecar);
            if matches!(self.store.get_state(&awaited), Ok(Some(_))) {
                ready.push(sidecar);
                continue;
            }
            self.queue_sidecar_awaiting_parent(awaited, sidecar);
        }
        self.send_data_columns_for_checks(ready);
    }

    /// Hand sidecars to the p2p layer's chain checks, which send back the
    /// ones that pass through `new_data_column_sidecars`.
    pub(crate) fn send_data_columns_for_checks(&self, sidecars: Vec<DataColumnSidecar>) {
        if sidecars.is_empty() {
            return;
        }
        let Some(ref p2p) = self.p2p else {
            return;
        };
        let _ = p2p.check_data_column_sidecars(sidecars).inspect_err(
            |err| error!(%err, "Failed to send data column sidecars to the p2p layer for checks"),
        );
    }

    /// Park `sidecar` against the parent root it could not be checked against.
    ///
    /// Counted as `queued_for_parent` rather than as a rejection: nothing about
    /// the sidecar has been judged yet, and conflating the two is what made the
    /// deadlock invisible in the metrics (every column read as
    /// `rejected{reason="unknown_parent"}` while the real fault was upstream).
    ///
    /// Nothing is refused here. The queue used to hold whole sidecars and so
    /// carried a count cap, which a follower behind the tip hit constantly:
    /// it receives gossip for the tip continuously, so the queue filled with
    /// sidecars for blocks it would not reach for minutes and then refused
    /// the ones for the block it was about to import. Measured on the eth-4
    /// follower a hundred slots behind, the queue sat pinned at its cap and
    /// dropped 2,561 sidecars in ten minutes while the chain ground through
    /// by-root lookups for slots whose columns gossip had already delivered
    /// and this function had thrown away. Evicting the furthest-ahead entry
    /// instead of the newest fixed which sidecar was lost, not that one was.
    ///
    /// The cap is gone now that the sidecars live in
    /// `Table::PendingDataColumns` and only their keys are held here, so what
    /// grows is disk rather than this actor's memory.
    /// [`Self::evict_sidecars_awaiting_parent_at_or_below_finality`] is what
    /// bounds it, which bounds how *long* an entry lives but not how fast
    /// they arrive: the chain checks do not require `parent_root` to name a
    /// block this node knows. Every sidecar reaching here, gossiped or
    /// fetched, has had its header's signature checked against the head state
    /// by those checks (`queue_unless_forged`, in
    /// `ethlambda_state_transition::beacon::gossip::column`), but only when a
    /// head state is already cached *and* the header's `proposer_index` names
    /// a validator in it: with no cached head state, or a proposer index that
    /// names none (`u64::MAX`, say), that check is skipped and a made-up
    /// header still reaches here and parks a row. A peer exploiting either
    /// gap can still park rows as fast as it can invent a slot, proposer and
    /// index, until finality catches up.
    pub(crate) fn queue_sidecar_awaiting_parent(
        &mut self,
        awaited: H256,
        sidecar: DataColumnSidecar,
    ) {
        let parked = ParkedColumn {
            slot: sidecar.slot(),
            block_root: sidecar.block_root(),
            index: sidecar.index(),
        };

        // A re-delivery of something already parked. The by-root and by-range
        // fetch paths skip gossip's seen cache entirely, so they never touch
        // the p2p actor's `SeenColumns` (which in any case only records an
        // Accept, never a park); a re-delivery reaching here is ordinary, and
        // without this check the same column would take a second slot in the
        // queue and leave a stale key behind after the first replay took its
        // row. Asked before the write rather than left to the set below,
        // because the write is what costs.
        if self
            .sidecars_awaiting_parent
            .get(&awaited)
            .is_some_and(|parked_columns| parked_columns.contains(&parked))
        {
            return;
        }

        // The bytes go to disk before the key goes in the map, so a failed
        // write leaves no key pointing at a row that is not there.
        if let Err(err) = self.store.put_pending_data_column(&sidecar) {
            error!(%err, "Failed to park a data column sidecar");
            return;
        }

        trace!(
            slot = parked.slot,
            column = parked.index,
            awaited = %ShortRoot(&awaited.0),
            "Queueing a data column sidecar until the block it is judged against has a post-state"
        );
        self.sidecars_awaiting_parent
            .entry(awaited)
            .or_default()
            .insert(parked);
        self.publish_sidecars_awaiting_parent();
    }

    /// Republish how many sidecars are parked, from the map that decides it.
    pub(crate) fn publish_sidecars_awaiting_parent(&self) {
        let total: usize = self
            .sidecars_awaiting_parent
            .values()
            .map(HashSet::len)
            .sum();
        metrics::set_sidecars_awaiting_parent(total as u64);
    }

    /// Send every sidecar parked against `block_root` back to the p2p layer's
    /// chain checks, now that it has a post-state to be checked against.
    ///
    /// Called from the one arm that means "this root now has a post-state".
    /// The ones that pass come back through `new_data_column_sidecars` as a
    /// new message, so nothing here re-enters the import path.
    pub(crate) fn drain_sidecars_awaiting_parent(&mut self, block_root: H256) {
        let Some(parked_columns) = self.sidecars_awaiting_parent.remove(&block_root) else {
            return;
        };
        debug!(
            parent_root = %ShortRoot(&block_root.0),
            count = parked_columns.len(),
            "Replaying data column sidecars whose parent just imported"
        );
        self.publish_sidecars_awaiting_parent();

        let mut sidecars = Vec::with_capacity(parked_columns.len());
        for parked in parked_columns {
            // Taken, not read: the row has served its purpose either way. A
            // replay that passes is written to `DataColumns`, and one that
            // fails a check has been judged, so neither leaves anything worth
            // keeping here.
            let sidecar = match self.store.take_pending_data_column(
                parked.slot,
                &parked.block_root,
                parked.index,
            ) {
                Ok(Some(sidecar)) => sidecar,
                Ok(None) => {
                    error!(
                        slot = parked.slot,
                        column = parked.index,
                        block_root = %ShortRoot(&parked.block_root.0),
                        "A parked data column sidecar has no row to replay from"
                    );
                    continue;
                }
                Err(err) => {
                    error!(%err, "Failed to read back a parked data column sidecar");
                    continue;
                }
            };
            sidecars.push(sidecar);
        }
        self.send_data_columns_for_checks(sidecars);
    }

    /// Drop parked sidecars whose block finality has superseded.
    ///
    /// The counterpart of [`Self::evict_held_blocks_at_or_below_finality`] and
    /// run beside it, for the same reason: a parent root that never arrives
    /// would otherwise pin its children's sidecars for this node's whole
    /// uptime. A sidecar at or below the finalized slot can never be needed
    /// again, since the chain checks would drop it outright now.
    pub(crate) fn evict_sidecars_awaiting_parent_at_or_below_finality(&mut self) {
        if self.sidecars_awaiting_parent.is_empty() {
            return;
        }
        let finalized_slot = self
            .store
            .latest_finalized()
            .expect("finalized checkpoint exists")
            .slot;

        let mut dropped: Vec<ParkedColumn> = Vec::new();
        self.sidecars_awaiting_parent.retain(|_, parked_columns| {
            parked_columns.retain(|parked| {
                let keep = parked.slot > finalized_slot;
                if !keep {
                    dropped.push(*parked);
                }
                keep
            });
            !parked_columns.is_empty()
        });

        if !dropped.is_empty() {
            info!(
                finalized_slot,
                count = dropped.len(),
                "Evicting parked data column sidecars that finality has superseded"
            );
            // The rows go with the keys, so a key dropped from the map never
            // leaves its bytes on disk with nothing left to read them.
            let keys = dropped
                .iter()
                .map(|parked| (parked.slot, parked.block_root, parked.index));
            let _ = self
                .store
                .delete_pending_data_column_sidecars(keys)
                .inspect_err(|err| error!(%err, "Failed to drop parked data column sidecars"));
            self.publish_sidecars_awaiting_parent();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{
        GENESIS_TIME, bare_state, beacon_server, beacon_server_recording, beacon_store,
        beacon_store_at_slot_10, gloas_sidecar_at, gloas_store_at_slot_10, sidecar_at,
    };
    use ethlambda_types::primitives::HashTreeRoot as _;

    #[test]
    fn a_data_column_sidecar_naming_a_parent_with_no_state_is_parked_not_stored() {
        // `beacon_store` writes no anchor state (see its own doc comment), so
        // any parent root at all is unknown here, including the anchor's own.
        let (mut server, p2p) = beacon_server_recording(beacon_store_at_slot_10());
        let parent_root = H256::repeat_byte(9);
        let sidecar = sidecar_at(10, parent_root);
        let block_root = sidecar.signed_block_header.message.hash_tree_root();

        server.park_data_columns(vec![DataColumnSidecar::Fulu(sidecar)]);

        // Not stored: it has not been checked, so it has not been accepted.
        assert_eq!(
            server
                .store
                .data_column_indices_for(10, &block_root)
                .unwrap(),
            Vec::<u64>::new()
        );
        // But kept, under the parent it is waiting on. Dropping it here is
        // what deadlocks a follower running the availability gate: a held
        // block writes no post-state, so every sidecar of every child of it
        // lands in exactly this branch.
        assert_eq!(
            server
                .sidecars_awaiting_parent
                .get(&parent_root)
                .map(HashSet::len),
            Some(1)
        );
        assert!(p2p.checks.lock().unwrap().is_empty());
    }

    #[test]
    fn a_sidecar_whose_parent_imported_meanwhile_goes_back_for_checks_not_into_the_queue() {
        // The race the p2p layer's checks open: they found no parent state,
        // then the parent imported and drained its (still empty) queue before
        // this message arrived. Parking it now would strand it until
        // finality, since that parent never drains again.
        let (mut server, p2p) = beacon_server_recording(beacon_store_at_slot_10());
        let parent_root = H256::repeat_byte(9);
        server
            .store
            .insert_state(parent_root, bare_state())
            .expect("insert");
        let sidecar = sidecar_at(10, parent_root);

        server.park_data_columns(vec![DataColumnSidecar::Fulu(sidecar.clone())]);

        assert!(server.sidecars_awaiting_parent.is_empty());
        assert_eq!(
            *p2p.checks.lock().unwrap(),
            vec![vec![DataColumnSidecar::Fulu(sidecar)]]
        );
    }

    #[test]
    fn a_parked_sidecar_goes_back_for_checks_once_its_parent_gains_a_post_state() {
        // The deadlock this closes, in miniature: while the parent has no
        // post-state every sidecar under it parks, and if parking were the end
        // of the story the queue would only ever grow. What breaks the cycle
        // is that gaining a post-state releases them, to the p2p layer's
        // checks, since this actor no longer judges a sidecar itself.
        let (mut server, p2p) = beacon_server_recording(beacon_store_at_slot_10());
        let parent_root = H256::repeat_byte(9);
        let sidecar = sidecar_at(10, parent_root);
        let block_root = sidecar.signed_block_header.message.hash_tree_root();

        server.park_data_columns(vec![DataColumnSidecar::Fulu(sidecar.clone())]);
        assert!(server.sidecars_awaiting_parent.contains_key(&parent_root));

        server.drain_sidecars_awaiting_parent(parent_root);

        // Gone from the queue and from `PendingDataColumns`, and handed to
        // the checks exactly as it was parked.
        assert!(!server.sidecars_awaiting_parent.contains_key(&parent_root));
        assert!(
            server
                .store
                .take_pending_data_column_sidecar(10, &block_root, 0)
                .expect("DB read should succeed")
                .is_none()
        );
        assert_eq!(
            *p2p.checks.lock().unwrap(),
            vec![vec![DataColumnSidecar::Fulu(sidecar)]]
        );
    }

    #[test]
    fn a_gloas_sidecar_for_an_unimported_block_parks_on_its_own_block_and_replays_when_it_imports()
    {
        // A gloas sidecar is judged against its own block (the commitments are
        // in its bid), so it waits on that block's post-state where a fulu one
        // waits on its parent's.
        let (mut server, p2p) = beacon_server_recording(gloas_store_at_slot_10());
        let block_root = H256::repeat_byte(5);
        let sidecar = gloas_sidecar_at(10, block_root, 3);

        server.park_data_columns(vec![sidecar.clone()]);

        assert_eq!(
            server.sidecars_awaiting_parent.get(&block_root),
            Some(&HashSet::from([ParkedColumn {
                slot: 10,
                block_root,
                index: 3,
            }]))
        );
        // Parked and not custodied.
        assert!(!server.store.has_data_column(10, &block_root, 3));
        assert!(p2p.checks.lock().unwrap().is_empty());

        // The block imports: what was waiting on it goes back for checks, as
        // it was parked.
        server.drain_sidecars_awaiting_parent(block_root);

        assert!(server.sidecars_awaiting_parent.is_empty());
        assert!(
            server
                .store
                .take_pending_data_column(10, &block_root, 3)
                .expect("DB read should succeed")
                .is_none()
        );
        assert_eq!(*p2p.checks.lock().unwrap(), vec![vec![sidecar]]);
    }

    #[test]
    fn a_gloas_sidecar_whose_block_has_a_state_goes_straight_back_for_checks() {
        let (mut server, p2p) = beacon_server_recording(gloas_store_at_slot_10());
        let block_root = H256::repeat_byte(5);
        server
            .store
            .insert_state(block_root, bare_state())
            .expect("insert");
        let sidecar = gloas_sidecar_at(10, block_root, 3);

        server.park_data_columns(vec![sidecar.clone()]);

        assert!(server.sidecars_awaiting_parent.is_empty());
        assert_eq!(*p2p.checks.lock().unwrap(), vec![vec![sidecar]]);
    }

    #[test]
    fn a_parked_sidecar_holds_its_bytes_on_disk_and_not_in_the_queue() {
        // The queue's size is chosen by whoever is gossiping, so what it holds
        // per entry is the thing that has to stay small: a key, not a cell per
        // blob.
        let mut server = beacon_server(beacon_store_at_slot_10());
        let parent_root = H256::repeat_byte(9);
        let sidecar = sidecar_at(10, parent_root);
        let block_root = sidecar.signed_block_header.message.hash_tree_root();

        server.park_data_columns(vec![DataColumnSidecar::Fulu(sidecar)]);

        assert_eq!(
            server.sidecars_awaiting_parent.get(&parent_root),
            Some(&HashSet::from([ParkedColumn {
                slot: 10,
                block_root,
                index: 0,
            }]))
        );
        assert!(
            server
                .store
                .take_pending_data_column_sidecar(10, &block_root, 0)
                .expect("DB read should succeed")
                .is_some(),
            "the sidecar's bytes belong in PendingDataColumns"
        );
    }

    #[test]
    fn a_parked_sidecar_does_not_satisfy_the_availability_gate() {
        // Why the parked rows get a table of their own. Nothing has judged a
        // parked sidecar's inclusion proof, its KZG batch or its proposer
        // signature, so a peer that could get one counted as custodied would
        // be able to release a held block with a column it invented.
        let mut server = beacon_server(beacon_store_at_slot_10());
        let sidecar = sidecar_at(10, H256::repeat_byte(9));
        let block_root = sidecar.signed_block_header.message.hash_tree_root();

        server.park_data_columns(vec![DataColumnSidecar::Fulu(sidecar)]);

        assert_eq!(
            server
                .store
                .data_column_indices_for(10, &block_root)
                .expect("DB read should succeed"),
            Vec::<u64>::new(),
            "an unverified sidecar must be invisible to data_column_indices_for"
        );
    }

    #[test]
    fn a_sidecar_parked_twice_takes_one_slot_in_the_queue() {
        // The by-root and by-range fetch paths skip gossip's seen cache
        // entirely, so nothing between them and this actor dedups a
        // re-delivery while the parent is still stateless; it is ordinary. A
        // second entry would leave a key with no row behind it once the
        // first replay took it.
        let mut server = beacon_server(beacon_store_at_slot_10());
        let parent_root = H256::repeat_byte(9);

        server.park_data_columns(vec![DataColumnSidecar::Fulu(sidecar_at(10, parent_root))]);
        server.park_data_columns(vec![DataColumnSidecar::Fulu(sidecar_at(10, parent_root))]);

        assert_eq!(
            server
                .sidecars_awaiting_parent
                .get(&parent_root)
                .map(HashSet::len),
            Some(1)
        );
    }

    #[test]
    fn parked_sidecars_are_dropped_once_finality_passes_their_slot() {
        // Populated directly rather than through `park_data_columns`: the
        // chain checks refuse a sidecar at or below the finalized slot before
        // it could ever be parked, so the only way to observe the sweep is to
        // park one behind their back. The finalized slot is fixed at init, so
        // the store carries it rather than the test moving it.
        let mut server = beacon_server(beacon_store(GENESIS_TIME, 10));
        let superseded = H256::repeat_byte(1);
        let still_wanted = H256::repeat_byte(2);
        let parked_at = |slot: u64| ParkedColumn {
            slot,
            block_root: H256::repeat_byte(9),
            index: 0,
        };
        server
            .sidecars_awaiting_parent
            .insert(superseded, HashSet::from([parked_at(10)]));
        server
            .sidecars_awaiting_parent
            .insert(still_wanted, HashSet::from([parked_at(20)]));

        server.evict_sidecars_awaiting_parent_at_or_below_finality();

        // A parent root that never arrives would otherwise pin its children's
        // sidecars for this node's whole uptime; one still above finality is
        // a parent that may yet show up.
        assert!(!server.sidecars_awaiting_parent.contains_key(&superseded));
        assert!(server.sidecars_awaiting_parent.contains_key(&still_wanted));
    }
}
