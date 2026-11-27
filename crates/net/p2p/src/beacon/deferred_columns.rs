//! Gossip verdicts held back for gloas data column sidecars until their
//! deferred validation decides.
//!
//! `gloas/p2p-interface.md`, on `data_column_sidecar_{subnet_id}`: "If the
//! sidecar fails deferred validation, its forwarding peers MUST be downscored
//! retroactively. If validation succeeds, the client MUST re-broadcast the
//! sidecar." A gloas sidecar is deferred when its block has not been seen, or
//! has been seen without a post-state yet (`Queue`): the chain actor parks it,
//! and hands it back through the chain checks ([`column_checks`]) once the
//! block imports.
//!
//! Gossipsub does both for a verdict reported late, and nothing else here
//! could. An `Accept` forwards the message gossipsub holds to the mesh, which
//! is the re-broadcast. A `Reject` applies the invalid-message penalty to the
//! peer the message came from and to every peer that sent a copy. Publishing
//! the sidecar again would send nothing: gossipsub keeps a received id in its
//! duplicate cache for the whole `seen_ttl` and refuses a publish of the same
//! bytes as `Duplicate`. And the `Ignore` every other queued message is
//! reported with at once removes the message from gossipsub's cache, leaving
//! nothing for a later verdict to act on.
//!
//! So such a sidecar's verdict is held here, with the sidecar, and reported
//! once the chain checks decide: `Accept` when the sidecar was handed to the
//! chain actor (the seen cache then decides, as for any accept, through
//! [`verdict::settle_message`]); the check's own outcome when it was dropped;
//! the original `Queue` when it was never judged. Either way the checks have
//! already handed the sidecar on or dropped it, so the verdict only tells
//! gossipsub.
//!
//! The limit is gossipsub's: it holds an unvalidated message for
//! [`MESSAGE_CACHE_WINDOW`] only. A verdict still held then is reported with
//! its original `Queue`, since gossipsub has dropped the message by that
//! time. A block that imports later still gets the column stored, but this
//! node neither relays it nor blames its senders.
//!
//! One verdict per `(block, index)`: valid sidecars of one block and index are
//! byte-identical, so another copy queued under a different message id is
//! reported at once, as before. The checks a held verdict waits on are its own
//! sidecar's: the first pass runs on it directly, and a recheck counts only
//! when the sidecar the chain actor parked is equal to it, since the actor
//! parks the first copy of each key it is given, which may be another
//! source's.

use std::collections::HashMap;
use std::time::Instant;

use ethlambda_state_transition::beacon::gossip::Outcome;
use ethlambda_types::beacon::containers::DataColumnSidecar;
use ethlambda_types::beacon::preset::NUMBER_OF_COLUMNS;
use ethlambda_types::beacon::primitives::Root;
use spawned_concurrency::tasks::Context;
use tracing::{debug, warn};

use crate::beacon::column_checks::{self, ColumnArrival, ColumnVerdict, Done};
use crate::beacon::verdict::{self, GossipId, Validated};
use crate::{MESSAGE_CACHE_WINDOW, P2PServer, p2p_protocol};

/// The most verdicts held at once: four blocks' worth of columns, more than a
/// supernode sees queued within one [`MESSAGE_CACHE_WINDOW`]. A sidecar that
/// finds it full is reported at once, as before.
const CAPACITY: usize = 4 * NUMBER_OF_COLUMNS;

/// One held verdict.
struct Held {
    id: GossipId,
    /// The `Queue` gossip judged it with, reported when nothing better is
    /// learned.
    queued: Outcome,
    sidecar: DataColumnSidecar,
}

/// The verdicts held, by `(block root, column index)`.
#[derive(Default)]
pub(crate) struct DeferredColumns {
    held: HashMap<(Root, u64), Held>,
}

impl DeferredColumns {
    /// Hold `id`'s verdict until `sidecar`'s checks decide. Gives `id` back
    /// when it cannot be held: the key already is, or the holding is full.
    /// An `Option` rather than a `Result`, since giving it back is no error.
    fn hold(
        &mut self,
        id: GossipId,
        queued: Outcome,
        sidecar: &DataColumnSidecar,
    ) -> Option<GossipId> {
        let key = (sidecar.block_root(), sidecar.index());
        if self.held.len() >= CAPACITY || self.held.contains_key(&key) {
            return Some(id);
        }
        let sidecar = sidecar.clone();
        self.held.insert(
            key,
            Held {
                id,
                queued,
                sidecar,
            },
        );
        None
    }

    /// Whether a verdict is held for `sidecar`'s key: `Some(true)` when its
    /// sidecar is this one, `Some(false)` when it is another copy. Only gloas
    /// sidecars are ever held, so a fulu one answers `None` without hashing
    /// its header for a block root.
    fn holds(&self, sidecar: &DataColumnSidecar) -> Option<bool> {
        let DataColumnSidecar::Gloas(gloas) = sidecar else {
            return None;
        };
        let held = self.held.get(&(gloas.beacon_block_root, gloas.index))?;
        Some(held.sidecar == *sidecar)
    }

    fn take(&mut self, key: &(Root, u64)) -> Option<Held> {
        self.held.remove(key)
    }

    /// Take every verdict held for [`MESSAGE_CACHE_WINDOW`] or longer.
    fn take_expired(&mut self, now: Instant) -> Vec<Held> {
        let expired: Vec<(Root, u64)> = self
            .held
            .iter()
            .filter(|(_, held)| {
                now.saturating_duration_since(held.id.received_at) >= MESSAGE_CACHE_WINDOW
            })
            .map(|(key, _)| *key)
            .collect();
        expired
            .iter()
            .filter_map(|key| self.held.remove(key))
            .collect()
    }

    pub(crate) fn len(&self) -> usize {
        self.held.len()
    }
}

/// Hold the verdict of a gloas sidecar gossip queued, and send the sidecar
/// through the chain checks, which report back here. Gives the id and the
/// sidecar back when the verdict cannot be held (see [`DeferredColumns::hold`]),
/// for the caller to report and forward as any other queued sidecar.
pub(crate) fn defer(
    server: &mut P2PServer,
    ctx: &Context<P2PServer>,
    id: GossipId,
    queued: Outcome,
    sidecar: Box<DataColumnSidecar>,
) -> Option<(GossipId, Box<DataColumnSidecar>)> {
    let now = Instant::now();
    report_expired(server, now);
    let received_at = id.received_at;
    if let Some(id) = server.deferred_columns.hold(id, queued, &sidecar) {
        return Some((id, sidecar));
    }
    let arrival = ColumnArrival::received("gossip", received_at);
    check(server, ctx, vec![*sidecar], arrival);
    None
}

/// Run the chain checks on sidecars the chain actor parked, handed back once
/// the block they wait on imported. The ones a held verdict waits on are
/// checked with a callback that settles it; the rest as before.
pub(crate) fn recheck(
    server: &mut P2PServer,
    ctx: &Context<P2PServer>,
    sidecars: Vec<DataColumnSidecar>,
) {
    if server.deferred_columns.len() == 0 {
        return column_checks::check_and_forward(server, sidecars, ColumnArrival::Recheck);
    }
    let mut awaited: HashMap<Root, Vec<DataColumnSidecar>> = HashMap::new();
    let mut rest = Vec::new();
    for sidecar in sidecars {
        match server.deferred_columns.holds(&sidecar) {
            Some(true) => awaited
                .entry(sidecar.block_root())
                .or_default()
                .push(sidecar),
            Some(false) => {
                // The actor parked another copy of this key, so the held one
                // is never judged: its queue verdict stands.
                let key = (sidecar.block_root(), sidecar.index());
                if let Some(held) = server.deferred_columns.take(&key) {
                    let queued = held.queued;
                    report_held(server, held, queued);
                }
                rest.push(sidecar);
            }
            None => rest.push(sidecar),
        }
    }
    if !rest.is_empty() {
        column_checks::check_and_forward(server, rest, ColumnArrival::Recheck);
    }
    for (_, group) in awaited {
        check(server, ctx, group, ColumnArrival::Recheck);
    }
}

/// [`column_checks::check_and_forward_then`] on `sidecars`, all of one block,
/// with a callback that sends their verdicts back to the p2p actor to
/// [`settle`].
fn check(
    server: &P2PServer,
    ctx: &Context<P2PServer>,
    sidecars: Vec<DataColumnSidecar>,
    arrival: ColumnArrival,
) {
    let Some(block_root) = sidecars.first().map(DataColumnSidecar::block_root) else {
        return;
    };
    let back = ctx.clone();
    let done: Done = Box::new(move |verdicts| {
        let message = p2p_protocol::DeferredColumnsChecked {
            block_root,
            verdicts,
        };
        let _ = back
            .send(message)
            .inspect_err(|err| warn!(%err, "Failed to settle deferred data column verdicts"));
    });
    column_checks::check_and_forward_then(server, sidecars, arrival, Some(done));
}

/// Report the held verdicts of `block_root`'s columns that `verdicts` decide.
/// A parked sidecar decides nothing yet: the recheck once its block imports
/// does.
pub(crate) fn settle(
    server: &mut P2PServer,
    block_root: Root,
    verdicts: Vec<(u64, ColumnVerdict)>,
) {
    for (index, verdict) in verdicts {
        if verdict == ColumnVerdict::Parked {
            continue;
        }
        let Some(held) = server.deferred_columns.take(&(block_root, index)) else {
            continue;
        };
        let outcome = match verdict {
            ColumnVerdict::Delivered => Outcome::Accept,
            ColumnVerdict::Dropped(outcome) => outcome,
            ColumnVerdict::Parked | ColumnVerdict::Unjudged => held.queued,
        };
        report_held(server, held, outcome);
    }
    report_expired(server, Instant::now());
}

/// Report every verdict held past [`MESSAGE_CACHE_WINDOW`] with its original
/// `Queue`: gossipsub no longer holds the message, so nothing else it could
/// be told would do anything.
pub(crate) fn report_expired(server: &mut P2PServer, now: Instant) {
    for held in server.deferred_columns.take_expired(now) {
        let queued = held.queued;
        report_held(server, held, queued);
    }
}

/// Report `outcome` for a held verdict. An `Accept` goes through the seen
/// cache first, as every accept does, and becomes `Ignore(AlreadySeen)` when
/// another copy of the key was accepted meanwhile.
fn report_held(server: &mut P2PServer, held: Held, outcome: Outcome) {
    let Held { id, sidecar, .. } = held;
    let (block_root, index) = (sidecar.block_root(), sidecar.index());
    let object = Validated::Column(Box::new(sidecar));
    let outcome = verdict::settle_message(server, &id.message_id, outcome, &object);
    let (outcome_label, reason) = outcome.labels();
    debug!(
        %block_root,
        index,
        outcome = outcome_label,
        reason,
        held_ms = id.received_at.elapsed().as_millis() as u64,
        "Reporting a deferred data column sidecar's verdict"
    );
    // The chain checks already handed the sidecar on or dropped it.
    let _ = verdict::report(server, id, outcome);
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ethlambda_state_transition::beacon::gossip::{IgnoreReason, QueueReason, RejectReason};
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::containers::gloas;
    use libp2p::PeerId;
    use libp2p::gossipsub::{MessageAcceptance, MessageId};
    use tokio::sync::mpsc::UnboundedReceiver;

    use super::*;
    use crate::swarm_adapter::{SwarmCommand, SwarmHandle};
    use crate::test_support::unconnected_beacon_server;

    const QUEUED: Outcome = Outcome::Queue(QueueReason::BlockUnknown);

    fn id(tag: u8, received_at: Instant) -> GossipId {
        GossipId {
            message_id: MessageId::new(&[tag]),
            propagation_source: PeerId::random(),
            received_at,
            kind: "data_column_sidecar",
        }
    }

    fn sidecar(root: u8, index: u64) -> DataColumnSidecar {
        DataColumnSidecar::Gloas(gloas::DataColumnSidecar {
            index,
            slot: 5,
            beacon_block_root: Root::repeat_byte(root),
            ..Default::default()
        })
    }

    /// The acceptances reported, in order.
    fn reported(commands: &mut UnboundedReceiver<SwarmCommand>) -> Vec<MessageAcceptance> {
        let mut acceptances = Vec::new();
        while let Ok(command) = commands.try_recv() {
            if let SwarmCommand::ReportValidation { acceptance, .. } = command {
                acceptances.push(acceptance);
            }
        }
        acceptances
    }

    #[test]
    fn one_verdict_is_held_per_block_and_index() {
        let mut deferred = DeferredColumns::default();
        let now = Instant::now();
        assert!(deferred.hold(id(1, now), QUEUED, &sidecar(1, 0)).is_none());
        assert!(deferred.hold(id(2, now), QUEUED, &sidecar(1, 0)).is_some());
        assert!(deferred.hold(id(3, now), QUEUED, &sidecar(1, 1)).is_none());

        assert_eq!(deferred.holds(&sidecar(1, 0)), Some(true));
        let mut other_copy = sidecar(1, 0);
        if let DataColumnSidecar::Gloas(gloas) = &mut other_copy {
            gloas.slot = 6;
        }
        assert_eq!(deferred.holds(&other_copy), Some(false));
        assert_eq!(deferred.holds(&sidecar(2, 0)), None);
    }

    #[test]
    fn a_verdict_expires_with_gossipsubs_message_cache() {
        let mut deferred = DeferredColumns::default();
        let start = Instant::now();
        assert!(
            deferred
                .hold(id(1, start), QUEUED, &sidecar(1, 0))
                .is_none()
        );
        let later = start + Duration::from_millis(500);
        assert!(
            deferred
                .hold(id(2, later), QUEUED, &sidecar(1, 1))
                .is_none()
        );

        let just_before = start + MESSAGE_CACHE_WINDOW - Duration::from_millis(1);
        assert!(deferred.take_expired(just_before).is_empty());
        let expired = deferred.take_expired(start + MESSAGE_CACHE_WINDOW);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].sidecar.index(), 0);
        assert_eq!(deferred.len(), 1);
    }

    #[test]
    fn the_holding_is_bounded() {
        let mut deferred = DeferredColumns::default();
        let now = Instant::now();
        for index in 0..CAPACITY as u64 {
            let root = (index / NUMBER_OF_COLUMNS as u64) as u8;
            let column = index % NUMBER_OF_COLUMNS as u64;
            assert!(
                deferred
                    .hold(id(0, now), QUEUED, &sidecar(root, column))
                    .is_none()
            );
        }
        assert!(
            deferred
                .hold(id(0, now), QUEUED, &sidecar(200, 0))
                .is_some()
        );
    }

    /// Each decided verdict reaches gossipsub as the specification asks:
    /// relayed when the checks passed, held against its senders when they
    /// refused it, and the queue's `Ignore` when it was never judged. A
    /// parked one waits.
    #[tokio::test]
    async fn the_checks_verdict_is_what_gossipsub_hears() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let (swarm_handle, mut commands) = SwarmHandle::capturing();
        server.swarm_handle = swarm_handle;
        let now = Instant::now();
        for index in 0..4 {
            let held =
                server
                    .deferred_columns
                    .hold(id(index as u8, now), QUEUED, &sidecar(1, index));
            assert!(held.is_none());
        }
        let root = Root::repeat_byte(1);

        settle(
            &mut server,
            root,
            vec![
                (0, ColumnVerdict::Delivered),
                (
                    1,
                    ColumnVerdict::Dropped(Outcome::Reject(RejectReason::Kzg)),
                ),
                (2, ColumnVerdict::Unjudged),
                (3, ColumnVerdict::Parked),
            ],
        );

        assert!(matches!(
            reported(&mut commands).as_slice(),
            [
                MessageAcceptance::Accept,
                MessageAcceptance::Reject,
                MessageAcceptance::Ignore
            ]
        ));
        assert!(server.seen_block_columns.contains(root, 0));
        assert!(!server.seen_block_columns.contains(root, 1));
        assert_eq!(server.deferred_columns.len(), 1, "column 3 is still parked");
    }

    /// A copy of the key accepted meanwhile takes the seen cache, so the held
    /// one is not relayed a second time.
    #[tokio::test]
    async fn a_held_column_whose_key_was_accepted_meanwhile_is_ignored() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let (swarm_handle, mut commands) = SwarmHandle::capturing();
        server.swarm_handle = swarm_handle;
        let root = Root::repeat_byte(1);
        let held = server
            .deferred_columns
            .hold(id(0, Instant::now()), QUEUED, &sidecar(1, 0));
        assert!(held.is_none());
        assert!(server.seen_block_columns.record(root, 0));

        settle(&mut server, root, vec![(0, ColumnVerdict::Delivered)]);

        assert!(matches!(
            reported(&mut commands).as_slice(),
            [MessageAcceptance::Ignore]
        ));
    }

    /// Already stored is not a judgment of this copy, so it is not relayed.
    #[tokio::test]
    async fn an_already_stored_column_is_not_relayed() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let (swarm_handle, mut commands) = SwarmHandle::capturing();
        server.swarm_handle = swarm_handle;
        let held = server
            .deferred_columns
            .hold(id(0, Instant::now()), QUEUED, &sidecar(1, 0));
        assert!(held.is_none());

        let stored = ColumnVerdict::Dropped(Outcome::Ignore(IgnoreReason::AlreadyStored));
        settle(&mut server, Root::repeat_byte(1), vec![(0, stored)]);

        assert!(matches!(
            reported(&mut commands).as_slice(),
            [MessageAcceptance::Ignore]
        ));
    }
}
