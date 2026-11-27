//! The sync gate's thresholds, shared by the two actors that act on them.
//!
//! The chain actor's sync tracker judges "behind" with these numbers, and the
//! p2p layer paces its `Status` refresh and gates the range syncs a refresh
//! answer may start by the same ones. Kept in one place so the two cannot
//! drift: a refresh cadence that no longer fits the lead it is meant to detect
//! is a silent sensitivity loss, not a compile error.

use ethlambda_types::beacon::preset;

/// How far behind a node may fall before it reports itself syncing, per chain.
///
/// The node is syncing only when **both** of these hold:
///
/// - its head trails the wall clock by more than [`Self::clock_lag`], which is
///   local evidence no peer can forge, and
/// - the head its peers report is more than [`Self::peer_lead`] slots ahead of
///   its own.
///
/// This is Lighthouse's and Prysm's shape. Lighthouse serves duties unless a
/// range sync is running *and* the head is over `sync_tolerance_epochs` (2)
/// behind the clock, and only a peer more than 32 slots ahead starts a range
/// sync. Prysm resyncs only when the head is two epochs behind the clock *and*
/// peers report a head two epochs ahead. Peers decide between "the network is
/// ahead of me" and "the network is stalled"; the clock keeps a peer's claim
/// from idling a node whose own head is current.
///
/// Only peers show a lead, from the first judgment on: a node that starts
/// behind the clock does its duties until a peer reports a head ahead of it,
/// as Lighthouse does in its initial `Stalled` state. Assuming the network is
/// at the clock instead would idle every node at once whenever all of them are
/// behind it (a slow network start, a restart after an outage), and a network
/// where nobody proposes stays stalled.
///
/// A peer's head is a claim, and a claim that never turns into progress is
/// bounded by [`Self::stall_window`]: syncing means getting somewhere, and a
/// lead nobody delivers reads the same as a stalled network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncThresholds {
    /// Slots the head may trail the wall clock before the node can be syncing.
    pub clock_lag: u64,
    /// The node can be syncing only once the peers' head leads ours by more
    /// than this many slots (a lead of exactly `peer_lead` is not enough).
    ///
    /// Also how far ahead a peer must be (more than this) before its answer
    /// to a `Status` *refresh*, or its own `Status` request, starts a range
    /// sync. A handshake answer starts one at any lead, but refreshes and
    /// requests land every few slots on a node that is keeping up with
    /// gossip, where a peer a slot ahead is ordinary and a one-block range
    /// request would only race gossip. Once syncing, the gate keeps counting
    /// a lead down through the [`Self::hysteresis`] band, where a refresh
    /// starts no range sync: a lead that small is filled by gossip and the
    /// parent lookups its blocks start, and a head that stays below it is
    /// bounded by [`Self::stall_window`] like any other.
    pub peer_lead: u64,
    /// Recovery band: once syncing, the node reports synced again only when
    /// the clock lag or the peer lead drops this many slots below its
    /// threshold, so the status does not flap at the boundary. The lead's
    /// threshold never drops below one slot, since a peer one slot ahead is
    /// ordinary propagation, so on lean (a lead threshold of one) the band
    /// applies to the clock lag alone.
    pub hysteresis: u64,
    /// Slots the node may read as syncing on a peer-reported lead without its
    /// head advancing, before it treats the network as stalled after all.
    /// Added up over every slot spent behind on the peers' word since the
    /// head last advanced, so a lead that lapses for a moment does not start
    /// the count over. A lead absent for longer than the window (an outage)
    /// does, once per head position, and the next claim gets a window of its
    /// own, unless the node has already given up on a lead at this head.
    ///
    /// A peer that claims a head it does not serve (an empty answer, invalid
    /// blocks, no answer) would otherwise keep a node that is behind the
    /// clock syncing for as long as it repeats the claim. A head advance
    /// starts the window over, so across advances the bound also rests on
    /// P2P: range sync sends the next batch to the peer with the highest
    /// head, and a peer that fails it cools down or becomes a suspect, after
    /// which its claim no longer counts. Sized above what can
    /// legitimately hold a catching-up head still: the range batch custody
    /// wait (30 s), an execution client's retry ladder (about 26 s), lean
    /// proof verification of a whole batch.
    pub stall_window: u64,
    /// How often the p2p layer re-asks each connected peer for its `Status`.
    ///
    /// A peer's report is up to this many slots stale when the tracker reads
    /// it, which shrinks the lead it shows by as much. [`Self::is_consistent`]
    /// keeps that staleness inside the clock threshold, so a node the clock
    /// says is behind still reads as behind its peers.
    pub status_refresh_slots: u64,
}

impl SyncThresholds {
    /// Lean consensus: leanSpec PR #708's lag threshold and hysteresis band,
    /// with the stall override replaced by the peer lead (see
    /// `docs/spec_deviations.md`). Lean has no epochs, so neither client's
    /// epoch-sized tolerance carries over.
    ///
    /// The peer lead is one slot rather than the clock's four because a
    /// report is up to [`Self::status_refresh_slots`] old: a node five slots
    /// behind a producing network sees peers that were current two slots ago
    /// at least two slots ahead, which a lead threshold of one detects. A lead
    /// of one is still not enough on its own: peers a single slot apart are
    /// ordinary propagation, and a run of missed proposals leaves every peer
    /// within that.
    pub const LEAN: Self = Self {
        clock_lag: 4,
        peer_lead: 1,
        hysteresis: 2,
        stall_window: 16,
        status_refresh_slots: 2,
    };

    /// The Beacon Chain: Lighthouse's numbers. Two epochs of clock lag
    /// (`DEFAULT_SYNC_TOLERANCE_EPOCHS`, Prysm's `shouldReSync` too) and a peer
    /// lead of one epoch (`SLOT_IMPORT_TOLERANCE`, the lead that makes a
    /// Lighthouse peer `Advanced`). Neither client has a hysteresis band, but
    /// neither re-judges on every block arrival either; this node does, and a
    /// follower importing about one block a slot right at the boundary would
    /// otherwise flip twice a slot. The stall window is an epoch, and the
    /// `Status` refresh is Prysm's half epoch (`maintainPeerStatuses`).
    ///
    /// Not a constant like [`Self::LEAN`]: every number but the hysteresis is
    /// a count of epochs, and the epoch's length is the preset's, which the
    /// process selects at startup.
    pub fn beacon() -> Self {
        Self::beacon_for(preset::slots_per_epoch())
    }

    /// [`Self::beacon`] for a preset with `slots_per_epoch` slots in an
    /// epoch. Apart from it so the bounds below are checked at compile time
    /// for each preset the node can run.
    pub const fn beacon_for(slots_per_epoch: u64) -> Self {
        Self {
            clock_lag: 2 * slots_per_epoch,
            peer_lead: slots_per_epoch,
            hysteresis: 4,
            stall_window: slots_per_epoch,
            status_refresh_slots: slots_per_epoch / 2,
        }
    }

    /// Slots a peer's `Status` report counts towards the network head after
    /// it arrived: four refresh intervals. That outlasts a refresh that times
    /// out (libp2p's 10 s) and the one after it, so a peer that misses an
    /// answer keeps its claim and a node behind it stays syncing, while a
    /// peer that has stopped answering altogether loses it. Expiry can only
    /// take a lead away.
    pub const fn report_lifetime(&self) -> u64 {
        4 * self.status_refresh_slots
    }

    /// Whether a report as stale as the refresh allows still shows the lead
    /// of a node the clock says is behind: a node just past
    /// [`Self::clock_lag`] behind peers that are a slot behind the clock and
    /// last reported [`Self::status_refresh_slots`] ago sees a lead of
    /// `clock_lag - status_refresh_slots`, which has to clear
    /// [`Self::peer_lead`].
    ///
    /// The bound assumes the refreshes are answered. A report kept past one
    /// that failed (see [`Self::report_lifetime`]) is older, and can show no
    /// lead at all (on lean, one as old as the lifetime shows none from a
    /// node just past the clock threshold). That node reads as synced until
    /// the peer answers again, as it would with the report expired: keeping a
    /// report can only add a lead, never take one away.
    pub const fn is_consistent(&self) -> bool {
        self.peer_lead + self.status_refresh_slots < self.clock_lag
            && self.hysteresis <= self.clock_lag
    }
}

const _: () = assert!(SyncThresholds::LEAN.is_consistent());
const _: () = assert!(SyncThresholds::beacon_for(preset::mainnet::SLOTS_PER_EPOCH).is_consistent());
const _: () = assert!(SyncThresholds::beacon_for(preset::minimal::SLOTS_PER_EPOCH).is_consistent());
