//! The validator's own clock.
//!
//! Seeded once from the beacon node's genesis, then independent of it. It is
//! deliberately not driven by the node's event stream: that stream is
//! best-effort by contract, dropping events for a slow subscriber, and a
//! dropped event must not mean a missed duty.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::constants::FAR_FUTURE_EPOCH;
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::preset::SLOTS_PER_EPOCH;
use ethlambda_types::beacon::primitives::{Epoch, Slot};

/// Basis points in a whole, which is what the duty offsets are expressed in.
const BASIS_POINTS: u64 = 10_000;

/// Converts wall-clock time to slots and back, for a chain whose genesis, slot
/// length and duty offsets are fixed for the life of the clock.
///
/// # Milliseconds and basis points, because the specification moved
///
/// The honest-validator guide used to name the duty offsets as fractions of a
/// `SECONDS_PER_SLOT`. Both halves of that are gone. The slot length is
/// `SLOT_DURATION_MS`, and the offsets are basis points of it:
/// `ATTESTATION_DUE_BPS` and `AGGREGATE_DUE_BPS`, evaluated with
/// `bps * SLOT_DURATION_MS // BASIS_POINTS`.
///
/// It is not a cosmetic change. On mainnet the attester offset is 3999 ms, not
/// the 4000 that a third of a 12-second slot gives, and the gloas fork moves
/// both offsets to 2500 and 5000 basis points, which no fixed fraction
/// expresses. Holding the basis points means this clock follows the network it
/// was told about rather than the one it was compiled for.
///
/// # The offsets depend on the fork of the slot
///
/// Gloas moves the attester and aggregator offsets earlier (2500 and 5000
/// basis points) and adds a payload timeliness committee deadline. So the clock
/// holds the whole [`Config`] and answers by the fork of the slot's own epoch
/// (`Config::fork_at_epoch`), which keeps a client running across the boundary
/// on the right offsets on both sides of it.
#[derive(Debug, Clone)]
pub struct SlotClock {
    genesis_time: u64,
    slot_duration_ms: u64,
    config: Config,
}

impl SlotClock {
    /// `genesis_time` is Unix seconds; the rest come from the beacon node's
    /// `/eth/v1/config/spec`.
    ///
    /// `slot_duration_ms` must be nonzero, since every slot computation divides
    /// by it. Callers taking it from a beacon node's response must reject a
    /// zero there, at the boundary where it can be reported as malformed input;
    /// this precondition is the backstop for any caller that does not.
    pub fn new(
        genesis_time: u64,
        slot_duration_ms: u64,
        attestation_due_bps: u64,
        aggregate_due_bps: u64,
    ) -> Self {
        let mut config = Config::mainnet().with_fork_epoch(ForkName::Gloas, FAR_FUTURE_EPOCH);
        config.slot_duration_ms = slot_duration_ms;
        config.attestation_due_bps = attestation_due_bps;
        config.aggregate_due_bps = aggregate_due_bps;
        Self::from_config(genesis_time, &config)
    }

    /// A clock for the network `config` describes, which is how the offsets
    /// of every fork reach it. See the type's docs for why it keeps the whole
    /// configuration rather than one pair of offsets.
    pub fn from_config(genesis_time: u64, config: &Config) -> Self {
        assert!(
            config.slot_duration_ms > 0,
            "slot_duration_ms must be nonzero"
        );
        Self {
            genesis_time,
            slot_duration_ms: config.slot_duration_ms,
            config: config.clone(),
        }
    }

    /// Whether `slot` is a gloas slot.
    pub fn is_gloas(&self, slot: Slot) -> bool {
        self.config.fork_at_epoch(self.epoch_of(slot)) >= ForkName::Gloas
    }

    /// The slot containing `now`, or `None` before genesis.
    ///
    /// Divides in milliseconds, not seconds, so a chain whose slot is not a
    /// whole number of seconds lands in the right slot rather than a rounded
    /// one.
    pub fn slot_at(&self, now: SystemTime) -> Option<Slot> {
        let since_epoch = now.duration_since(UNIX_EPOCH).ok()?;
        let since_genesis = since_epoch.checked_sub(Duration::from_secs(self.genesis_time))?;
        let elapsed_ms = u64::try_from(since_genesis.as_millis()).unwrap_or(u64::MAX);
        Some(elapsed_ms / self.slot_duration_ms)
    }

    /// The current slot, or `None` before genesis.
    pub fn now(&self) -> Option<Slot> {
        self.slot_at(SystemTime::now())
    }

    /// The epoch containing `slot`.
    pub fn epoch_of(&self, slot: Slot) -> Epoch {
        slot / SLOTS_PER_EPOCH
    }

    /// When `slot` begins.
    pub fn start_of(&self, slot: Slot) -> SystemTime {
        // Saturating rather than wrapping: a slot number large enough to
        // overflow this product is centuries away at any real slot duration,
        // and a clock that wrapped would put it in the past.
        UNIX_EPOCH
            + Duration::from_secs(self.genesis_time)
            + Duration::from_millis(slot.saturating_mul(self.slot_duration_ms))
    }

    /// When the attester duty for `slot` should run.
    pub fn attestation_time(&self, slot: Slot) -> SystemTime {
        let bps = if self.is_gloas(slot) {
            self.config.attestation_due_bps_gloas
        } else {
            self.config.attestation_due_bps
        };
        self.offset_into(slot, bps)
    }

    /// When the payload timeliness committee's duty for `slot` should run.
    ///
    /// Only meaningful for a gloas slot; the offset is the configured one
    /// whatever the slot, and callers gate on [`Self::is_gloas`].
    pub fn payload_attestation_time(&self, slot: Slot) -> SystemTime {
        self.offset_into(slot, self.config.payload_attestation_due_bps)
    }

    /// When the aggregation duty for `slot` should run.
    ///
    /// After the attester offset on every network the specification ships,
    /// necessarily: an aggregator folds together votes its beacon node has
    /// collected, and before the attesters have voted there is nothing to fold.
    pub fn aggregation_time(&self, slot: Slot) -> SystemTime {
        let bps = if self.is_gloas(slot) {
            self.config.aggregate_due_bps_gloas
        } else {
            self.config.aggregate_due_bps
        };
        self.offset_into(slot, bps)
    }

    /// When the sync committee message for `slot` is signed.
    ///
    /// The fork of `slot` picks the offset, as it does for attestations:
    /// gloas moves it earlier.
    pub fn sync_message_time(&self, slot: Slot) -> SystemTime {
        let bps = if self.is_gloas(slot) {
            self.config.sync_message_due_bps_gloas
        } else {
            self.config.sync_message_due_bps
        };
        self.offset_into(slot, bps)
    }

    /// When a sync committee aggregator publishes its contribution for `slot`.
    pub fn contribution_time(&self, slot: Slot) -> SystemTime {
        let bps = if self.is_gloas(slot) {
            self.config.contribution_due_bps_gloas
        } else {
            self.config.contribution_due_bps
        };
        self.offset_into(slot, bps)
    }

    /// `bps` basis points of the way into `slot`.
    ///
    /// The specification's own `get_slot_component_duration_ms`, which is
    /// `bps * SLOT_DURATION_MS // BASIS_POINTS`: integer arithmetic on
    /// milliseconds, multiplying before dividing. Doing it in `Duration`
    /// instead would keep nanoseconds and land 0.4 ms past the spec's answer on
    /// mainnet, which is wrong in the direction that matters for a deadline.
    fn offset_into(&self, slot: Slot, bps: u64) -> SystemTime {
        let offset_ms = bps.saturating_mul(self.slot_duration_ms) / BASIS_POINTS;
        self.start_of(slot) + Duration::from_millis(offset_ms)
    }

    /// When `slot` ends, which is when the next one begins.
    pub fn end_of(&self, slot: Slot) -> SystemTime {
        self.start_of(slot + 1)
    }

    /// How much of `slot` is left at `now`, or zero once it has passed.
    ///
    /// This is the budget a slot's duty gets. An attestation is for one slot,
    /// and the next slot's duty is due the moment this one ends, so work still
    /// running past that point is not merely late, it is competing with the
    /// duty that replaced it.
    ///
    /// Zero rather than an error for a slot already gone, so a caller can pass
    /// the result straight to a timeout: a duty that is already too late gets
    /// no budget and fails immediately, which is the correct outcome and not a
    /// case worth branching on.
    pub fn remaining_in(&self, slot: Slot, now: SystemTime) -> Duration {
        self.end_of(slot)
            .duration_since(now)
            .unwrap_or(Duration::ZERO)
    }

    /// How long from `now` until the attester duty for `slot`, or zero once
    /// that instant has passed.
    ///
    /// Two jobs, which is why it is one function. It is how long the duty loop
    /// sleeps between a slot's proposal work and its attestation work, and it
    /// is the budget the proposal work gets: a proposer that is still waiting
    /// on its beacon node when the attestation is due has already lost the
    /// block, and must not also cost this client's attesters their votes.
    ///
    /// Zero rather than an error once the instant is past, so an overrunning
    /// slot attests immediately and late rather than not at all.
    pub fn until_attestation(&self, slot: Slot, now: SystemTime) -> Duration {
        self.attestation_time(slot)
            .duration_since(now)
            .unwrap_or(Duration::ZERO)
    }

    /// How long from `now` until the aggregation duty for `slot`, or zero once
    /// that instant has passed.
    ///
    /// The aggregation counterpart to [`Self::until_attestation`], and the
    /// budget aggregation gets: an aggregate that arrives after its slot ends
    /// is competing with the next slot's duties, and the votes it carries have
    /// already had a whole slot to reach a block by another route.
    pub fn until_aggregation(&self, slot: Slot, now: SystemTime) -> Duration {
        self.aggregation_time(slot)
            .duration_since(now)
            .unwrap_or(Duration::ZERO)
    }

    /// How long from `now` until the payload timeliness committee's duty for
    /// `slot`, or zero once that instant has passed.
    ///
    /// The PTC counterpart to [`Self::until_aggregation`]: the loop sleeps on
    /// it between aggregation and the committee vote.
    pub fn until_payload_attestation(&self, slot: Slot, now: SystemTime) -> Duration {
        self.payload_attestation_time(slot)
            .duration_since(now)
            .unwrap_or(Duration::ZERO)
    }

    /// How long from `now` until the sync committee message for `slot`, or zero
    /// once that instant has passed.
    pub fn until_sync_message(&self, slot: Slot, now: SystemTime) -> Duration {
        self.sync_message_time(slot)
            .duration_since(now)
            .unwrap_or(Duration::ZERO)
    }

    /// How long from `now` until the contribution for `slot`, or zero once
    /// that instant has passed.
    pub fn until_contribution(&self, slot: Slot, now: SystemTime) -> Duration {
        self.contribution_time(slot)
            .duration_since(now)
            .unwrap_or(Duration::ZERO)
    }

    /// How long from `now` until the first of `slot`'s duties that does not
    /// wait on another: the attestation or the sync committee message.
    ///
    /// What the loop sleeps between a slot's proposal and the rest of its
    /// duties. Sleeping on the attestation alone would hold a sync message
    /// back when the network moves it earlier (gloas does).
    pub fn until_first_slot_duty(&self, slot: Slot, now: SystemTime) -> Duration {
        self.until_attestation(slot, now)
            .min(self.until_sync_message(slot, now))
    }

    /// The next slot to serve, given the last one served, and how long until
    /// it begins.
    ///
    /// This is what drives the duty loop: one wake per slot, at the boundary,
    /// from which the slot's own offsets are reached by sleeping further in.
    /// A proposer publishes at the boundary and an attester one third in, so a
    /// loop that woke only at the attester offset could never propose.
    ///
    /// # Why it takes the slot already served
    ///
    /// Because "the next slot after now" is the wrong answer when the previous
    /// slot's work ran long. A slot's duties are bounded by that slot's end, so
    /// a hung beacon node can return the loop to this function at, or just
    /// after, the following slot's boundary. Answering "the slot after the one
    /// we are standing in" would then sleep straight past a slot whose
    /// attestation was still seconds away, and one hung request would cost two
    /// slots of duties rather than one, which is the cascade the per-slot
    /// budget exists to prevent.
    ///
    /// So when the clock has already entered a slot later than the one served,
    /// that slot is returned with no delay. Its own offsets degrade to zero on
    /// their own, so its attestation goes out late rather than not at all.
    ///
    /// Otherwise the answer is the slot after the one served, which is also
    /// what keeps the loop from spinning: finishing inside the slot just served
    /// must not return that slot again.
    ///
    /// `served` is `None` only on the first call. The client is then somewhere
    /// inside a slot it is too late to propose for, and has no duties yet
    /// anyway, so it waits for the next boundary.
    ///
    /// Before genesis this returns slot 0 and the wait until it. A client
    /// started early sleeps once, exactly until genesis, instead of waking
    /// every slot-length to ask again.
    pub fn next_slot_to_serve(&self, served: Option<Slot>, now: SystemTime) -> (Slot, Duration) {
        let Some(current) = self.slot_at(now) else {
            let delay = self
                .start_of(0)
                .duration_since(now)
                .unwrap_or(Duration::ZERO);
            return (0, delay);
        };

        let next = match served {
            // The previous slot's work overran into this one, or past it.
            // Serve where the clock actually is.
            Some(served) if current > served => current,
            // Finished inside the slot served, or the wall clock stepped
            // backwards. Either way, move on rather than serve it twice: the
            // guards would refuse the duties anyway, and repeating a slot is
            // how a loop like this spins.
            Some(served) => served + 1,
            None => current + 1,
        };
        let delay = self
            .start_of(next)
            .duration_since(now)
            .unwrap_or(Duration::ZERO);
        (next, delay)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GENESIS: u64 = 1_000_000;
    const SECONDS_PER_SLOT: u64 = 12;
    /// Mainnet's values, so the numbers in these tests are the real ones.
    const ATTESTATION_DUE_BPS: u64 = 3_333;
    const AGGREGATE_DUE_BPS: u64 = 6_667;

    fn clock() -> SlotClock {
        SlotClock::new(
            GENESIS,
            SECONDS_PER_SLOT * 1_000,
            ATTESTATION_DUE_BPS,
            AGGREGATE_DUE_BPS,
        )
    }

    fn at(offset_secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(GENESIS + offset_secs)
    }

    #[test]
    fn a_slot_ends_where_the_next_begins() {
        let clock = clock();
        assert_eq!(clock.end_of(0), clock.start_of(1));
        assert_eq!(clock.end_of(5), at(6 * SECONDS_PER_SLOT));
    }

    #[test]
    fn the_budget_is_what_is_left_of_the_slot() {
        let clock = clock();
        // Two seconds into slot 3, ten of its twelve seconds remain.
        let now = at(3 * SECONDS_PER_SLOT + 2);
        assert_eq!(clock.remaining_in(3, now), Duration::from_secs(10));
    }

    #[test]
    fn the_budget_at_a_slot_boundary_is_a_whole_slot() {
        let clock = clock();
        assert_eq!(
            clock.remaining_in(3, clock.start_of(3)),
            Duration::from_secs(SECONDS_PER_SLOT)
        );
    }

    /// A duty already past its slot gets no budget rather than an error or a
    /// wrapped-around one, so the caller can pass this straight to a timeout
    /// and have a hopeless duty fail at once.
    #[test]
    fn a_slot_already_gone_has_no_budget_left() {
        let clock = clock();
        let well_past = at(10 * SECONDS_PER_SLOT);
        assert_eq!(clock.remaining_in(3, well_past), Duration::ZERO);
    }

    #[test]
    fn slot_zero_starts_at_genesis() {
        assert_eq!(clock().slot_at(at(0)), Some(0));
        assert_eq!(clock().slot_at(at(11)), Some(0));
        assert_eq!(clock().slot_at(at(12)), Some(1));
    }

    #[test]
    fn before_genesis_there_is_no_slot() {
        let before = UNIX_EPOCH + Duration::from_secs(GENESIS - 1);
        assert_eq!(clock().slot_at(before), None);
    }

    #[test]
    fn an_epoch_is_slots_per_epoch_slots() {
        let clock = clock();
        assert_eq!(clock.epoch_of(0), 0);
        assert_eq!(clock.epoch_of(SLOTS_PER_EPOCH - 1), 0);
        assert_eq!(clock.epoch_of(SLOTS_PER_EPOCH), 1);
    }

    /// 3333 basis points of a 12-second slot is 3999 ms, not the 4000 a third
    /// would give. The one-millisecond difference is what the integer floor in
    /// the specification's own formula produces, and getting it by dividing
    /// into thirds instead is how this was wrong before.
    #[test]
    fn the_attester_duty_runs_at_the_specifications_basis_points() {
        let clock = clock();
        let duty = clock.attestation_time(10);
        let start = clock.start_of(10);
        assert_eq!(
            duty.duration_since(start).expect("after the start"),
            Duration::from_millis(3_999)
        );
    }

    /// 6667 basis points of a 12-second slot is exactly 8000 ms, which happens
    /// to equal two thirds. It is asserted against the basis points rather than
    /// the fraction, because the two only coincide here.
    #[test]
    fn the_aggregation_duty_runs_at_the_specifications_basis_points() {
        let clock = clock();
        let duty = clock.aggregation_time(10);
        let start = clock.start_of(10);
        assert_eq!(
            duty.duration_since(start).expect("after the start"),
            Duration::from_millis(8_000)
        );
    }

    /// A gloas-era configuration moves both offsets, which no fixed fraction of
    /// a slot expresses. This is what holding the basis points buys.
    #[test]
    fn a_different_basis_point_configuration_moves_both_offsets() {
        let clock = SlotClock::new(GENESIS, 12_000, 2_500, 5_000);
        let start = clock.start_of(10);
        assert_eq!(
            clock
                .attestation_time(10)
                .duration_since(start)
                .expect("after the start"),
            Duration::from_millis(3_000)
        );
        assert_eq!(
            clock
                .aggregation_time(10)
                .duration_since(start)
                .expect("after the start"),
            Duration::from_millis(6_000)
        );
    }

    /// A slot length that is not a whole number of seconds has to work at all,
    /// which the old whole-second clock could not express.
    #[test]
    fn a_sub_second_slot_length_lands_in_the_right_slot() {
        let clock = SlotClock::new(GENESIS, 1_500, 3_333, 6_667);
        let at_ms = |ms: u64| UNIX_EPOCH + Duration::from_millis(GENESIS * 1_000 + ms);

        assert_eq!(clock.slot_at(at_ms(0)), Some(0));
        assert_eq!(clock.slot_at(at_ms(1_499)), Some(0));
        assert_eq!(clock.slot_at(at_ms(1_500)), Some(1));
        assert_eq!(clock.slot_at(at_ms(3_000)), Some(2));
        assert_eq!(clock.start_of(2), at_ms(3_000));
    }

    /// Aggregation must come after attestation. An aggregator folds votes its
    /// beacon node has collected, and before the attesters have voted there is
    /// nothing to fold.
    #[test]
    fn aggregation_comes_after_attestation_in_every_slot() {
        let clock = clock();
        for slot in [0, 1, 10, 1000] {
            assert!(clock.aggregation_time(slot) > clock.attestation_time(slot));
            assert!(clock.aggregation_time(slot) < clock.end_of(slot));
        }
    }

    #[test]
    fn the_wait_until_aggregation_is_the_rest_of_the_offset() {
        let clock = clock();
        // Five seconds into slot 5, whose aggregation runs eight seconds in.
        let now = at(5 * SECONDS_PER_SLOT + 5);
        assert_eq!(clock.until_aggregation(5, now), Duration::from_secs(3));
    }

    #[test]
    fn an_overrun_slot_leaves_no_time_to_aggregate() {
        let clock = clock();
        assert_eq!(
            clock.until_aggregation(5, at(5 * SECONDS_PER_SLOT + 11)),
            Duration::ZERO
        );
    }

    #[test]
    fn the_next_slot_to_serve_is_the_one_after_the_one_served() {
        // Two seconds into slot 5, having just served it.
        let now = at(5 * SECONDS_PER_SLOT + 2);
        let (slot, delay) = clock().next_slot_to_serve(Some(5), now);
        assert_eq!(slot, 6);
        assert_eq!(delay, Duration::from_secs(10));
    }

    /// Finishing exactly on the following boundary must not skip that slot.
    ///
    /// This is the shape a hung beacon node produces: a slot's duties are
    /// bounded by that slot's end, so the timeout fires precisely here.
    /// Answering "the slot after the one we are standing in" would sleep past
    /// slot 6 entirely, and its attestation was still a third of a slot away.
    #[test]
    fn work_that_overran_into_the_next_slot_serves_that_slot_at_once() {
        let clock = clock();
        let (slot, delay) = clock.next_slot_to_serve(Some(5), clock.start_of(6));
        assert_eq!(slot, 6, "the overrun must not cost slot 6 its duties");
        assert_eq!(delay, Duration::ZERO);
    }

    /// The same, a nanosecond later, which is where a `>` versus `>=` slip
    /// would show up.
    #[test]
    fn work_that_overran_by_a_nanosecond_still_serves_that_slot() {
        let clock = clock();
        let now = clock.start_of(6) + Duration::from_nanos(1);
        let (slot, delay) = clock.next_slot_to_serve(Some(5), now);
        assert_eq!(slot, 6);
        assert_eq!(delay, Duration::ZERO);
    }

    /// A badly overrunning slot lands several slots later. Serve where the
    /// clock is, not where the sequence says it should be.
    #[test]
    fn work_that_overran_by_several_slots_serves_the_current_one() {
        let clock = clock();
        let (slot, delay) = clock.next_slot_to_serve(Some(5), at(9 * SECONDS_PER_SLOT + 1));
        assert_eq!(slot, 9);
        assert_eq!(delay, Duration::ZERO);
    }

    /// The property that keeps the loop from spinning: finishing inside the
    /// slot just served must move on to the next one, not offer it again.
    #[test]
    fn finishing_inside_the_slot_served_does_not_serve_it_twice() {
        let clock = clock();
        let (slot, delay) = clock.next_slot_to_serve(Some(5), clock.start_of(5));
        assert_eq!(slot, 6);
        assert_eq!(delay, Duration::from_secs(SECONDS_PER_SLOT));
    }

    /// A backwards wall-clock step must move forward too, for the same reason.
    ///
    /// The client then idles until the stepped-back clock reaches slot 10
    /// again, which is the right outcome: slots 5 through 9 have already been
    /// served, and the duties for a slot that has not happened yet cannot be
    /// fetched. This is the case the guards exist for, and here the clock never
    /// even offers them the chance.
    #[test]
    fn a_backwards_clock_step_does_not_serve_an_old_slot_again() {
        let clock = clock();
        let now = at(5 * SECONDS_PER_SLOT);
        let (slot, delay) = clock.next_slot_to_serve(Some(9), now);
        assert_eq!(slot, 10, "never go back over a slot already served");
        assert_eq!(
            now + delay,
            clock.start_of(10),
            "the wait must reach slot 10, not expire early"
        );
    }

    /// On the first call the client is mid-slot with no duties yet, so it
    /// waits for the next boundary rather than serving the slot it is in.
    #[test]
    fn the_first_slot_served_is_the_next_boundary() {
        let now = at(5 * SECONDS_PER_SLOT + 2);
        let (slot, delay) = clock().next_slot_to_serve(None, now);
        assert_eq!(slot, 6);
        assert_eq!(delay, Duration::from_secs(10));
    }

    /// Before genesis the client sleeps once, exactly until slot 0, rather
    /// than waking every slot-length to ask whether the chain has started.
    #[test]
    fn before_genesis_the_next_slot_is_zero_and_the_wait_reaches_it() {
        let clock = clock();
        let now = UNIX_EPOCH + Duration::from_secs(GENESIS - 30);
        let (slot, delay) = clock.next_slot_to_serve(None, now);
        assert_eq!(slot, 0);
        assert_eq!(delay, Duration::from_secs(30));
        assert_eq!(now + delay, clock.start_of(0));
    }

    /// Slots before the gloas epoch keep the pre-gloas offsets and slots from
    /// it on take the gloas ones, on both sides of the boundary.
    #[test]
    fn the_offsets_change_at_the_gloas_boundary() {
        let config = Config::mainnet().with_fork_epoch(ForkName::Gloas, 2);
        let clock = SlotClock::from_config(GENESIS, &config);
        let last_fulu = 2 * SLOTS_PER_EPOCH - 1;
        let first_gloas = 2 * SLOTS_PER_EPOCH;
        let ms =
            |t: SystemTime, slot: u64| t.duration_since(clock.start_of(slot)).expect("after start");

        assert!(!clock.is_gloas(last_fulu));
        assert!(clock.is_gloas(first_gloas));
        assert_eq!(
            ms(clock.attestation_time(last_fulu), last_fulu),
            Duration::from_millis(3_999)
        );
        assert_eq!(
            ms(clock.aggregation_time(last_fulu), last_fulu),
            Duration::from_millis(8_000)
        );
        assert_eq!(
            ms(clock.attestation_time(first_gloas), first_gloas),
            Duration::from_millis(3_000)
        );
        assert_eq!(
            ms(clock.aggregation_time(first_gloas), first_gloas),
            Duration::from_millis(6_000)
        );
    }

    #[test]
    fn the_sync_offsets_follow_the_fork_of_the_slot() {
        let config = Config::mainnet().with_fork_epoch(ForkName::Gloas, 2);
        let clock = SlotClock::from_config(GENESIS, &config);
        let last_fulu = 2 * SLOTS_PER_EPOCH - 1;
        let first_gloas = 2 * SLOTS_PER_EPOCH;
        let ms =
            |t: SystemTime, slot: u64| t.duration_since(clock.start_of(slot)).expect("after start");

        assert_eq!(
            ms(clock.sync_message_time(last_fulu), last_fulu),
            Duration::from_millis(3_999)
        );
        assert_eq!(
            ms(clock.contribution_time(last_fulu), last_fulu),
            Duration::from_millis(8_000)
        );
        assert_eq!(
            ms(clock.sync_message_time(first_gloas), first_gloas),
            Duration::from_millis(3_000)
        );
        assert_eq!(
            ms(clock.contribution_time(first_gloas), first_gloas),
            Duration::from_millis(6_000)
        );
    }

    #[test]
    fn the_wait_until_the_sync_message_is_the_rest_of_the_offset() {
        let clock = clock();
        let now = at(5 * SECONDS_PER_SLOT + 1);
        assert_eq!(
            clock.until_sync_message(5, now),
            Duration::from_millis(2_999)
        );
        assert_eq!(
            clock.until_contribution(5, now),
            Duration::from_millis(6_999)
        );
        assert_eq!(
            clock.until_sync_message(5, at(5 * SECONDS_PER_SLOT + 9)),
            Duration::ZERO
        );
    }

    #[test]
    fn the_first_slot_duty_is_the_earlier_of_attestation_and_sync_message() {
        let mut config = Config::mainnet().with_fork_epoch(ForkName::Gloas, 100);
        config.sync_message_due_bps = 2_000;
        let clock = SlotClock::from_config(GENESIS, &config);
        let start = clock.start_of(5);
        assert_eq!(
            clock.until_first_slot_duty(5, start),
            Duration::from_millis(2_400),
            "the sync message is due before the attestation"
        );
        assert_eq!(
            clock.until_first_slot_duty(5, start + Duration::from_secs(10)),
            Duration::ZERO
        );
    }

    #[test]
    fn the_payload_attestation_deadline_is_three_quarters_in() {
        let config = Config::mainnet().with_fork_epoch(ForkName::Gloas, 0);
        let clock = SlotClock::from_config(GENESIS, &config);
        let slot = 5;
        assert_eq!(
            clock.until_payload_attestation(slot, clock.start_of(slot)),
            Duration::from_millis(9_000)
        );
        assert_eq!(
            clock.until_payload_attestation(slot, clock.start_of(slot) + Duration::from_secs(10)),
            Duration::ZERO
        );
    }

    #[test]
    fn the_wait_until_the_attester_duty_is_the_rest_of_the_offset() {
        let clock = clock();
        // One second into slot 5, whose duty runs 3999 ms in.
        let now = at(5 * SECONDS_PER_SLOT + 1);
        assert_eq!(
            clock.until_attestation(5, now),
            Duration::from_millis(2_999)
        );
    }

    #[test]
    fn a_whole_slot_boundary_leaves_the_full_offset_to_propose_in() {
        let clock = clock();
        assert_eq!(
            clock.until_attestation(5, clock.start_of(5)),
            Duration::from_millis(3_999)
        );
    }

    /// A proposal that overran its budget must leave zero, not an error and
    /// not a wrapped-around wait: the caller sleeps on this value, so a
    /// wrapped one would stall the loop for years.
    #[test]
    fn an_overrun_proposal_leaves_no_time_before_the_attestation() {
        let clock = clock();
        let past_the_offset = at(5 * SECONDS_PER_SLOT + 9);
        assert_eq!(clock.until_attestation(5, past_the_offset), Duration::ZERO);
    }
}
