//! Whether this client's clock agrees with its beacon nodes', and whether it
//! stepped.
//!
//! Every duty is timed off this client's own wall clock ([`SlotClock`]), and
//! nothing else ever looks at that clock. Ahead by more than half a second, an
//! ethlambda node refuses its block requests as for a slot that has not
//! started; ahead by a few seconds, its attestations vote for the parent;
//! behind, every duty goes out late and nothing is refused at all. So the
//! client compares its clock with each beacon node's on the per-slot sync probe
//! ([`crate::beacon_node::health`]), and watches its own clock for steps.
//!
//! Everything here only warns, and sets a gauge or a counter. A disagreement
//! does not say which of the two clocks is off, and no duty is withheld for
//! one.
//!
//! # Two comparisons on each probe
//!
//! - **By slot** ([`compare_slots`]). A node imports no block from more than a
//!   slot past its own clock, so a head more than one slot past this client's
//!   wall slot means this client's clock is behind (Lighthouse's
//!   `TimeDiscrepancy` check). Where the node measures `sync_distance` from its
//!   own clock, `head_slot + sync_distance` is its wall slot, and one outside
//!   this client's wall slots at send and at receive means the clocks are most
//!   of a slot or more apart. Taking both sides of the request is what keeps a
//!   slot boundary inside the round trip from counting.
//! - **By `Date`** ([`date_offset`]). The header the node's HTTP server writes,
//!   less the midpoint of the round trip. Good to about a second, so only an
//!   offset of [`SKEW_THRESHOLD_SECS`] or more is warned about, and only once
//!   [`SAMPLES`] samples are kept. A node whose answers carry no `Date` gets
//!   the slot comparison alone.
//!
//! # Steps
//!
//! [`StepWatch`] compares how far the wall clock moved over each pass of the
//! duty loop with how far the monotonic clock did. The duty loop serves the
//! slot the wall clock reads, so a step forward skips slots and a step back
//! makes the loop wait for the wall clock to catch up.

use std::collections::VecDeque;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ethlambda_types::beacon::preset::slots_per_epoch;
use ethlambda_types::beacon::primitives::Slot;
use tracing::{info, warn};

use crate::beacon_node::health::{Probe, SyncStatus};
use crate::slot_clock::SlotClock;

/// A `Date` estimate this far from zero, or farther, is warned about. A kept
/// sample is within about a second of the truth (see [`MAX_ROUND_TRIP`]), so
/// a node with a synced clock never reads this far off, and one 3 s off always
/// does.
const SKEW_THRESHOLD_SECS: f64 = 2.0;

/// How many `Date` samples a node's estimate is the median of, and how many
/// must be kept before it is read: three, one a slot.
///
/// Not for averaging. The probe goes out at the same point of every slot, so
/// when a slot is a whole number of seconds, as on every network the
/// specification ships, the header's truncation error is about the same on
/// every sample and no number of them averages it away ([`date_offset`]
/// centres it instead). The median is there against one bad sample, from
/// either clock stepping while a request was out. Three ignore one such sample
/// and still report within three slots.
const SAMPLES: usize = 3;

/// How many slots a `Date` sample is read for: twice the span [`SAMPLES`]
/// take. A slow round trip or two leaves the estimate standing, and a node
/// that stops sending a usable `Date` loses it within this many slots, rather
/// than keeping an old skew warned about and on its gauge for good.
const SAMPLE_SLOTS: Slot = 2 * SAMPLES as Slot;

/// The longest round trip a `Date` sample is kept from. The node wrote the
/// header somewhere inside the round trip, so half of it bounds that error;
/// with the header's own half second, a kept sample is within a second of the
/// truth.
const MAX_ROUND_TRIP: Duration = Duration::from_secs(1);

/// Half the `Date` header's resolution. The header truncates: it names the
/// second the node's clock was in, anywhere in it. Its middle is the estimate.
const HALF_SECOND: Duration = Duration::from_millis(500);

/// How much more or less the wall clock must move than the monotonic clock,
/// over one pass of the duty loop, to count as a step. Half a second,
/// `MAXIMUM_GOSSIP_CLOCK_DISPARITY`: the smallest error that already costs a
/// proposal against an ethlambda node. Far above how the two clocks drift
/// apart over a pass, since an NTP slew moves the wall clock by milliseconds a
/// slot, and Linux slews its monotonic clock along with it.
const STEP_THRESHOLD_SECS: f64 = 0.5;

const DAY_NAMES: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// The instant an HTTP `Date` header names, in the IMF-fixdate form
/// (`Sun, 06 Nov 1994 08:49:37 GMT`), the one RFC 9110 has every server send.
/// `None` for anything else, the two obsolete forms included: a node whose
/// header does not parse gets the slot comparison alone.
pub fn parse_http_date(value: &str) -> Option<SystemTime> {
    // "Sun, 06 Nov 1994 08:49:37 GMT": a fixed layout, every field a fixed
    // width, so each one is a slice at a known offset.
    if value.len() != 29 || !value.is_ascii() {
        return None;
    }
    let bytes = value.as_bytes();
    let separators = [
        (3, b','),
        (4, b' '),
        (7, b' '),
        (11, b' '),
        (16, b' '),
        (19, b':'),
        (22, b':'),
    ];
    if separators.iter().any(|&(at, byte)| bytes[at] != byte) || &value[25..] != " GMT" {
        return None;
    }
    if !DAY_NAMES.contains(&&value[..3]) {
        return None;
    }
    let day = number(&value[5..7])?;
    let month = MONTHS.iter().position(|month| *month == &value[8..11])? as u64 + 1;
    let year = number(&value[12..16])?;
    let hour = number(&value[17..19])?;
    let minute = number(&value[20..22])?;
    // 60 is a leap second, which IMF-fixdate allows.
    let second = number(&value[23..25])?;
    if year < 1970
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let seconds = days_since_epoch(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second;
    Some(UNIX_EPOCH + Duration::from_secs(seconds))
}

/// A field of ASCII digits only: `u64::from_str` also takes a leading `+`.
fn number(field: &str) -> Option<u64> {
    if field.bytes().all(|byte| byte.is_ascii_digit()) {
        field.parse().ok()
    } else {
        None
    }
}

fn days_in_month(year: u64, month: u64) -> u64 {
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days from 1970-01-01 to the given date, from 1970 on: Howard Hinnant's
/// `days_from_civil`, which counts years from March so the leap day falls at
/// the end of one.
fn days_since_epoch(year: u64, month: u64, day: u64) -> u64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year / 400;
    let year_of_era = year - era * 400;
    let month_from_march = (month + 9) % 12;
    let day_of_year = (153 * month_from_march + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// `later - earlier` in seconds, negative when `later` is the earlier one.
fn seconds_between(later: SystemTime, earlier: SystemTime) -> f64 {
    match later.duration_since(earlier) {
        Ok(ahead) => ahead.as_secs_f64(),
        Err(behind) => -behind.duration().as_secs_f64(),
    }
}

/// One `Date` sample: the node's clock minus this client's, in seconds, from
/// a request sent at `sent` and answered at `received` with `date`.
///
/// `date`, moved to the middle of the second it names, less the midpoint of
/// the round trip. `None` for a round trip longer than [`MAX_ROUND_TRIP`], too
/// long to bound where in it the node wrote the header, or one that ends before
/// it starts, which only a step back of this client's clock produces.
pub fn date_offset(sent: SystemTime, received: SystemTime, date: SystemTime) -> Option<f64> {
    let round_trip = received.duration_since(sent).ok()?;
    if round_trip > MAX_ROUND_TRIP {
        return None;
    }
    let midpoint = sent + round_trip / 2;
    Some(seconds_between(date + HALF_SECOND, midpoint))
}

/// A slot comparison that shows the two clocks apart.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SlotSkew {
    /// The node's slot the comparison rests on: its wall slot, or its head
    /// when the node's `sync_distance` does not give its wall slot.
    pub node_slot: Slot,
    /// This client's wall slot it was compared with: at receive when the node
    /// is ahead, at send when it is behind.
    pub client_slot: Slot,
    /// Of the offsets the comparison allows, node minus client in seconds, the
    /// one nearest zero: positive when this client's clock is behind.
    pub offset_bound: f64,
}

impl SlotSkew {
    /// The node's clock is ahead of this client's, so this client's is
    /// behind, rather than the other way round.
    pub fn client_is_behind(&self) -> bool {
        self.node_slot > self.client_slot
    }
}

/// Whether the node's answer to a probe sent at `sent` and answered at
/// `received` puts its clock in another slot than this client's. `None` when
/// the clocks agree to the slot, or the answer cannot say.
///
/// Two rules, read by what the node reported:
///
/// - **`sync_distance` above zero, not syncing.** `head_slot + sync_distance`
///   is then the node's own wall slot, as Lighthouse, Prysm, Nimbus and
///   ethlambda compute the distance. One before this client's wall slot at
///   send means this client's clock is ahead; one past its wall slot at
///   receive, behind. A boundary inside the round trip lands between the two
///   and counts as neither. Not read at zero, or while the node syncs, since
///   neither then gives the node's clock: the Beacon API defines the distance
///   as how many slots the node has to process to reach the head, and Teku
///   reports 0 whenever it is in sync and its peers' best slot less its head
///   while it syncs, so a missed slot would read as this client being ahead.
/// - **Otherwise, the head alone**, Lighthouse's `TimeDiscrepancy` check: a
///   head more than one slot past this client's wall slot at receive means
///   this client's clock is behind. Nothing can tell a node behind from a head
///   that is merely old, so this rule never says this client is ahead.
pub fn compare_slots(
    clock: &SlotClock,
    status: &SyncStatus,
    sent: SystemTime,
    received: SystemTime,
) -> Option<SlotSkew> {
    let (Some(sent_slot), Some(received_slot)) = (clock.slot_at(sent), clock.slot_at(received))
    else {
        return None;
    };
    // This client's clock stepped back while the request was out.
    if received_slot < sent_slot {
        return None;
    }
    let head = status.head_slot?;
    let distance = status
        .sync_distance
        .filter(|&distance| distance > 0 && !status.is_syncing);
    if let Some(distance) = distance {
        let node_slot = head.checked_add(distance)?;
        // The node read its clock between `sent` and `received`.
        return if node_slot > received_slot {
            Some(SlotSkew {
                node_slot,
                client_slot: received_slot,
                offset_bound: seconds_between(clock.start_of(node_slot), received),
            })
        } else if node_slot < sent_slot {
            Some(SlotSkew {
                node_slot,
                client_slot: sent_slot,
                offset_bound: seconds_between(clock.start_of(node_slot + 1), sent),
            })
        } else {
            None
        };
    }
    // With a slot of tolerance, the node's clock is at least in the slot
    // before its head's.
    (head > received_slot.saturating_add(1)).then(|| SlotSkew {
        node_slot: head,
        client_slot: received_slot,
        offset_bound: seconds_between(clock.start_of(head - 1), received),
    })
}

/// What one node's answer to one probe says about the two clocks.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Reading {
    /// The node's clock minus this client's, in seconds, as well as it is
    /// known: the `Date` estimate once there is one, held to the bound of a
    /// slot comparison that shows the clocks apart; else that bound; else
    /// zero.
    pub offset: f64,
    /// The median of the node's last [`SAMPLES`] `Date` samples, once that
    /// many are kept from the last [`SAMPLE_SLOTS`] slots.
    pub date_offset: Option<f64>,
    /// The slot comparison, when it shows the clocks apart.
    pub slots: Option<SlotSkew>,
}

impl Reading {
    /// Whether the clocks are far enough apart to warn about.
    pub fn is_skewed(&self) -> bool {
        self.slots.is_some()
            || self
                .date_offset
                .is_some_and(|offset| offset.abs() >= SKEW_THRESHOLD_SECS)
    }
}

/// Whether a node's reading is logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Report {
    /// The clocks disagree: the first reading that says so, or the first an
    /// epoch after the last warning.
    Warn,
    /// The clocks agree again after a warning.
    Agree,
    Quiet,
}

/// One node's clock across probes.
#[derive(Debug, Default)]
struct NodeClock {
    /// The last [`SAMPLES`] `Date` samples kept, oldest first, each with the
    /// slot of the probe it came from.
    samples: VecDeque<(Slot, f64)>,
    /// The slot of the last warning about this node.
    warned_at: Option<Slot>,
    /// A warning was logged and no agreement since.
    unresolved: bool,
}

impl NodeClock {
    fn keep(&mut self, slot: Slot, sample: f64) {
        if self.samples.len() == SAMPLES {
            self.samples.pop_front();
        }
        self.samples.push_back((slot, sample));
    }

    /// Drop the samples more than [`SAMPLE_SLOTS`] older than `slot`.
    fn forget_before(&mut self, slot: Slot) {
        let oldest = slot.saturating_sub(SAMPLE_SLOTS);
        self.samples.retain(|&(taken, _)| taken >= oldest);
    }

    fn estimate(&self) -> Option<f64> {
        if self.samples.len() < SAMPLES {
            return None;
        }
        let mut sorted: Vec<f64> = self.samples.iter().map(|&(_, sample)| sample).collect();
        sorted.sort_by(f64::total_cmp);
        sorted.get(SAMPLES / 2).copied()
    }

    /// At most one warning an epoch per node, and one line when the clocks
    /// agree again, so a skew that lasts, or one that flickers around the
    /// threshold, does not log every slot.
    fn report(&mut self, slot: Slot, skewed: bool) -> Report {
        if !skewed {
            return if std::mem::take(&mut self.unresolved) {
                Report::Agree
            } else {
                Report::Quiet
            };
        }
        let due = self
            .warned_at
            .is_none_or(|warned| slot >= warned.saturating_add(slots_per_epoch()));
        if !due {
            return Report::Quiet;
        }
        self.warned_at = Some(slot);
        self.unresolved = true;
        Report::Warn
    }
}

/// Every node's clock against this client's, read from each round of probes.
pub struct ClockWatch {
    clock: SlotClock,
    /// By command-line position.
    nodes: Vec<NodeClock>,
}

impl ClockWatch {
    pub fn new(clock: SlotClock) -> Self {
        Self {
            clock,
            nodes: Vec::new(),
        }
    }

    /// Read the probes taken for `slot`, every node's in command-line order (a
    /// [`crate::beacon_node::health::NodeHealth::snapshot`]): set each
    /// answering node's gauge and drop the others', and warn about each node
    /// whose clock disagrees with this client's, at most once an epoch.
    pub fn observe(&mut self, slot: Slot, probes: &[Option<Probe>]) {
        self.nodes.resize_with(probes.len(), NodeClock::default);
        for (position, probe) in probes.iter().enumerate() {
            // A node that did not answer has no offset to report: its series
            // goes, rather than keeping a value nothing current supports.
            let Some(reading) = self.read(position, slot, probe.as_ref()) else {
                crate::metrics::clear_beacon_node_clock_offset(position);
                continue;
            };
            crate::metrics::set_beacon_node_clock_offset(position, reading.offset);
            let Some(node) = self.nodes.get_mut(position) else {
                continue;
            };
            match node.report(slot, reading.is_skewed()) {
                Report::Warn => warn_skew(position, &reading),
                Report::Agree => info!(
                    position,
                    offset_seconds = %format_args!("{:+.1}", reading.offset),
                    "Beacon node's clock agrees with this client's again"
                ),
                Report::Quiet => {}
            }
        }
    }

    /// What the node at `position` said in the probe taken for `slot`, with
    /// its `Date` sample kept. `None` for a node that did not answer that
    /// probe.
    fn read(&mut self, position: usize, slot: Slot, probe: Option<&Probe>) -> Option<Reading> {
        let probe = probe.filter(|probe| probe.slot == slot)?;
        let (Ok(status), Some(reply)) = (&probe.outcome, probe.reply) else {
            return None;
        };
        let node = self.nodes.get_mut(position)?;
        let sample = reply
            .date
            .and_then(|date| date_offset(probe.at, reply.received, date));
        if let Some(sample) = sample {
            node.keep(slot, sample);
        }
        node.forget_before(slot);
        let date_offset = node.estimate();
        let slots = compare_slots(&self.clock, status, probe.at, reply.received);
        // The estimate, held to what the slots prove when they disagree with
        // it: a `Date` written by anything but the node (a reverse proxy
        // writes its own) is another clock's.
        let offset = match (date_offset, slots) {
            (Some(date), Some(skew)) if skew.client_is_behind() => date.max(skew.offset_bound),
            (Some(date), Some(skew)) => date.min(skew.offset_bound),
            (Some(date), None) => date,
            (None, Some(skew)) => skew.offset_bound,
            (None, None) => 0.0,
        };
        Some(Reading {
            offset,
            date_offset,
            slots,
        })
    }
}

fn warn_skew(position: usize, reading: &Reading) {
    let offset_seconds = format!("{:+.1}", reading.offset);
    let node_slot = reading.slots.map(|skew| skew.node_slot);
    let client_slot = reading.slots.map(|skew| skew.client_slot);
    let client_is_behind = reading
        .slots
        .map_or(reading.offset >= 0.0, |skew| skew.client_is_behind());
    if client_is_behind {
        warn!(
            position,
            %offset_seconds,
            ?node_slot,
            ?client_slot,
            "Beacon node's clock is ahead of this client's. If this client's is the one off, every \
             duty goes out late and nothing refuses it: blocks lose proposer boost, attestations \
             miss the head. Check time sync on both hosts"
        );
    } else {
        warn!(
            position,
            %offset_seconds,
            ?node_slot,
            ?client_slot,
            "Beacon node's clock is behind this client's. If this client's is the one off, duties \
             go out early: a node refuses a block request for a slot it has not reached, and \
             attestations vote for the parent. Check time sync on both hosts"
        );
    }
}

/// A discontinuity the duty loop found in its own clock between two passes.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Discontinuity {
    /// The wall clock moved `seconds` further than the monotonic clock
    /// (forward), or less (negative, backward).
    Step {
        seconds: f64,
        /// The slot the loop served last.
        served: Slot,
        /// The slot the wall clock reads now, `None` before genesis.
        wall_slot: Option<Slot>,
    },
    /// The wall clock did not step, but reads more than one slot past the
    /// slot served last: the loop itself was held up. A duty overran, or the
    /// process, or its virtual machine, was paused.
    Stalled { served: Slot, wall_slot: Slot },
}

/// One pass of the duty loop, by both clocks.
#[derive(Debug, Clone, Copy)]
struct Mark {
    wall: SystemTime,
    mono: Instant,
}

/// The duty loop's own clock, watched for steps across passes.
///
/// A step back of the wall clock past the slot just served, or one forward
/// past the next, is what the loop cannot absorb quietly: the first makes it
/// wait for the clock to come back, the second makes it skip the slots in
/// between (see [`SlotClock::next_slot_to_serve`]). Checked against the
/// monotonic clock rather than by slot alone, so an epoch refresh that
/// overran into a later slot is not taken for a step, and a slew across a
/// boundary is not either.
#[derive(Debug, Default)]
pub struct StepWatch {
    last: Option<Mark>,
}

impl StepWatch {
    /// Check the clock at the top of a pass, `served` being the slot the last
    /// pass served: log and count a step, log a stall.
    pub fn check(&mut self, clock: &SlotClock, served: Option<Slot>) {
        match self.observe(clock, served, SystemTime::now(), Instant::now()) {
            Some(Discontinuity::Step {
                seconds,
                served,
                wall_slot,
            }) => {
                crate::metrics::inc_clock_steps();
                let step_seconds = format!("{seconds:+.1}");
                // What the step does to the slots: forward past the next one,
                // the ones between are lost; back before the one served, the
                // loop waits for it again. Inside those bounds it only moves
                // the next boundary by its size.
                let skipped = wall_slot.is_some_and(|wall| wall > served.saturating_add(1));
                let went_back = wall_slot.is_none_or(|wall| wall < served);
                if seconds > 0.0 && skipped {
                    warn!(
                        %served,
                        ?wall_slot,
                        %step_seconds,
                        "Wall clock stepped forward: duties go to the slot it now reads, and the \
                         slots it jumped over are lost"
                    );
                } else if seconds < 0.0 && went_back {
                    warn!(
                        %served,
                        ?wall_slot,
                        %step_seconds,
                        "Wall clock stepped back: duties wait until it reaches the slot after the \
                         one served"
                    );
                } else {
                    warn!(
                        %served,
                        ?wall_slot,
                        %step_seconds,
                        "Wall clock stepped, within the slot served or into the next: no slot is \
                         lost, and the next boundary moves by the step"
                    );
                }
            }
            Some(Discontinuity::Stalled { served, wall_slot }) => warn!(
                %served,
                %wall_slot,
                "The duty loop came back more than a slot after the slot it served, with no clock \
                 step: a duty overran, or the process was paused. The slots in between are lost"
            ),
            None => {}
        }
    }

    /// [`Self::check`] at `wall` and `mono`, without logging.
    fn observe(
        &mut self,
        clock: &SlotClock,
        served: Option<Slot>,
        wall: SystemTime,
        mono: Instant,
    ) -> Option<Discontinuity> {
        let last = self.last.replace(Mark { wall, mono })?;
        let served = served?;
        let seconds = seconds_between(wall, last.wall)
            - mono.saturating_duration_since(last.mono).as_secs_f64();
        let wall_slot = clock.slot_at(wall);
        if seconds.abs() >= STEP_THRESHOLD_SECS {
            return Some(Discontinuity::Step {
                seconds,
                served,
                wall_slot,
            });
        }
        wall_slot
            .filter(|&wall_slot| wall_slot > served.saturating_add(1))
            .map(|wall_slot| Discontinuity::Stalled { served, wall_slot })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::beacon_node::fallback::FallbackBeaconNode;
    use crate::beacon_node::health::Reply;
    use crate::beacon_node::mock::MockBeaconNode;

    const GENESIS: u64 = 1_000_000;
    const SLOT_MS: u64 = 12_000;

    fn clock() -> SlotClock {
        SlotClock::new(GENESIS, SLOT_MS, 3_333, 6_667)
    }

    fn at_ms(since_genesis_ms: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(GENESIS) + Duration::from_millis(since_genesis_ms)
    }

    fn slot_ms(slot: Slot) -> u64 {
        slot * SLOT_MS
    }

    fn status(head_slot: Slot, sync_distance: u64) -> SyncStatus {
        SyncStatus {
            head_slot: Some(head_slot),
            sync_distance: Some(sync_distance),
            is_syncing: false,
            is_optimistic: false,
            el_offline: false,
        }
    }

    #[test]
    fn an_imf_fixdate_parses_to_its_instant() {
        assert_eq!(
            parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(UNIX_EPOCH + Duration::from_secs(784_111_777))
        );
        assert_eq!(
            parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT"),
            Some(UNIX_EPOCH)
        );
        assert_eq!(
            parse_http_date("Thu, 29 Feb 2024 00:00:00 GMT"),
            Some(UNIX_EPOCH + Duration::from_secs(1_709_164_800))
        );
    }

    /// The two obsolete forms, and anything malformed, are no `Date` at all.
    #[test]
    fn anything_but_an_imf_fixdate_is_refused() {
        for value in [
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "Sun Nov  6 08:49:37 1994",
            "Sun, 06 Nov 1994 08:49:37 UTC",
            "Sun, 06 Nov 1994 08:49:37 GMT ",
            "Sun, 31 Feb 1994 08:49:37 GMT",
            "Fri, 29 Feb 2023 08:49:37 GMT",
            "Sun, 06 Nov 1994 24:00:00 GMT",
            "Sun, 06 Foo 1994 08:49:37 GMT",
            "Abc, 06 Nov 1994 08:49:37 GMT",
            "Sun, +6 Nov 1994 08:49:37 GMT",
            "Sun, 06 Nov 1969 08:49:37 GMT",
            "Sun, 06 Nov 1994 08:49:37 GM\u{e9}",
            "",
        ] {
            assert_eq!(parse_http_date(value), None, "{value:?}");
        }
    }

    /// The header's second is read at its middle, and the round trip's at its
    /// midpoint.
    #[test]
    fn a_date_sample_is_the_middle_of_its_second_less_the_round_trips_midpoint() {
        let sent = at_ms(10_000);
        let received = at_ms(10_200);
        let date = at_ms(13_000);
        let sample = date_offset(sent, received, date).expect("kept");
        assert!((sample - 3.4).abs() < 1e-9, "{sample}");
    }

    #[test]
    fn a_long_or_backward_round_trip_is_not_a_sample() {
        let date = at_ms(10_000);
        assert_eq!(date_offset(at_ms(10_000), at_ms(11_500), date), None);
        assert_eq!(date_offset(at_ms(10_000), at_ms(9_900), date), None);
    }

    /// A probe of a node whose clock is `skew_ms` ahead of this client's,
    /// sent `phase_ms` into a second, 2 s before the boundary of `slot`, with
    /// a head and distance that agree with the client's slot.
    fn probe(slot: Slot, skew_ms: i64, phase_ms: u64) -> Probe {
        let sent_ms = slot_ms(slot) - 2_000 + phase_ms;
        let received_ms = sent_ms + 40;
        let node_ms = (GENESIS * 1_000 + sent_ms + 20) as i64 + skew_ms;
        let date = UNIX_EPOCH + Duration::from_secs(node_ms as u64 / 1_000);
        Probe {
            slot,
            at: at_ms(sent_ms),
            outcome: Ok(status(slot - 1, 0)),
            reply: Some(Reply {
                received: at_ms(received_ms),
                date: Some(date),
            }),
        }
    }

    /// The issue's second-level case: 3 s off is flagged, in either
    /// direction, once three samples are kept and not before; 1 s off never
    /// is, whatever the sub-second point the probe goes out at.
    #[test]
    fn a_three_second_skew_is_flagged_after_three_samples_and_one_second_never() {
        for phase_ms in [0, 250, 500, 750, 950] {
            for (skew_ms, flagged) in [
                (3_000, true),
                (-3_000, true),
                (1_000, false),
                (-1_000, false),
            ] {
                let mut watch = ClockWatch::new(clock());
                watch.nodes.resize_with(1, NodeClock::default);
                for (taken, slot) in (10..14).enumerate() {
                    let reading = watch
                        .read(0, slot, Some(&probe(slot, skew_ms, phase_ms)))
                        .expect("answered");
                    assert_eq!(reading.slots, None);
                    let expect = flagged && taken + 1 >= SAMPLES;
                    assert_eq!(
                        reading.is_skewed(),
                        expect,
                        "skew {skew_ms} ms, phase {phase_ms} ms, sample {taken}: {reading:?}"
                    );
                    if taken + 1 >= SAMPLES {
                        let estimate = reading.date_offset.expect("enough samples");
                        assert!((estimate * 1_000.0 - skew_ms as f64).abs() <= 1_000.0);
                        assert_eq!(reading.offset, estimate);
                    } else {
                        assert_eq!(reading.date_offset, None);
                        assert_eq!(reading.offset, 0.0);
                    }
                }
            }
        }
    }

    /// One wild sample among three does not move the median.
    #[test]
    fn one_bad_sample_does_not_flag_a_node() {
        let mut node = NodeClock::default();
        for (slot, sample) in [(1, 0.1), (2, 30.0), (3, -0.2)] {
            node.keep(slot, sample);
        }
        assert_eq!(node.estimate(), Some(0.1));
    }

    /// A node that stops sending a `Date` loses its estimate once its samples
    /// are more than [`SAMPLE_SLOTS`] old, so an old skew is not warned about
    /// for good; until then the estimate stands.
    #[test]
    fn an_estimate_from_old_samples_is_dropped() {
        let mut watch = ClockWatch::new(clock());
        watch.nodes.resize_with(1, NodeClock::default);
        for slot in 10..13 {
            let reading = watch.read(0, slot, Some(&probe(slot, 3_000, 0)));
            assert_eq!(reading.expect("answered").is_skewed(), slot == 12);
        }
        let dateless = |slot| {
            let mut probe = probe(slot, 3_000, 0);
            probe.reply = probe.reply.map(|reply| Reply {
                date: None,
                ..reply
            });
            probe
        };
        let last_read = 10 + SAMPLE_SLOTS;
        let held = watch.read(0, last_read, Some(&dateless(last_read)));
        assert!(held.expect("answered").date_offset.is_some());
        let next = last_read + 1;
        let dropped = watch
            .read(0, next, Some(&dateless(next)))
            .expect("answered");
        assert_eq!(dropped.date_offset, None);
        assert!(!dropped.is_skewed());
    }

    /// A node whose answers carry no `Date` is read by the slot comparison
    /// alone, which agrees here.
    #[test]
    fn a_node_without_a_date_reads_zero_when_the_slots_agree() {
        let mut watch = ClockWatch::new(clock());
        watch.nodes.resize_with(1, NodeClock::default);
        let mut probe = probe(10, 3_000, 0);
        probe.reply = probe.reply.map(|reply| Reply {
            date: None,
            ..reply
        });
        for _ in 0..4 {
            let reading = watch.read(0, 10, Some(&probe)).expect("answered");
            assert_eq!(
                reading,
                Reading {
                    offset: 0.0,
                    date_offset: None,
                    slots: None
                }
            );
        }
    }

    /// Only the probe taken for the slot is read, and only an answer.
    #[test]
    fn a_probe_for_another_slot_or_without_an_answer_is_not_read() {
        let mut watch = ClockWatch::new(clock());
        watch.nodes.resize_with(1, NodeClock::default);
        assert_eq!(watch.read(0, 11, Some(&probe(10, 0, 0))), None);
        let failed = Probe {
            outcome: Err("down".to_string()),
            reply: None,
            ..probe(10, 0, 0)
        };
        assert_eq!(watch.read(0, 10, Some(&failed)), None);
        assert_eq!(watch.read(0, 10, None), None);
    }

    /// Lighthouse's check: a head two slots past this client's wall slot
    /// means this client is behind; one slot past is tolerated.
    #[test]
    fn a_head_two_slots_past_the_clients_clock_means_the_client_is_behind() {
        let clock = clock();
        let sent = at_ms(slot_ms(10) - 2_000);
        let received = at_ms(slot_ms(10) - 1_950);

        let skew = compare_slots(&clock, &status(11, 0), sent, received).expect("behind");
        assert_eq!((skew.node_slot, skew.client_slot), (11, 9));
        assert!(skew.offset_bound > 0.0);

        assert_eq!(compare_slots(&clock, &status(10, 0), sent, received), None);
    }

    /// A node's wall slot, from a distance it measured off its own clock,
    /// past this client's at receive: this client is behind.
    #[test]
    fn a_node_wall_slot_past_the_clients_means_the_client_is_behind() {
        let clock = clock();
        let sent = at_ms(slot_ms(10) - 2_000);
        let received = at_ms(slot_ms(10) - 1_950);
        let skew = compare_slots(&clock, &status(8, 2), sent, received).expect("behind");
        assert_eq!((skew.node_slot, skew.client_slot), (10, 9));
        assert!((skew.offset_bound - 1.95).abs() < 1e-9);
    }

    /// The node's wall slot before this client's at send: this client is
    /// ahead, by most of a slot at least, since the probe goes out late in it.
    #[test]
    fn a_node_wall_slot_before_the_clients_means_the_client_is_ahead() {
        let clock = clock();
        let sent = at_ms(slot_ms(10) - 2_000);
        let received = at_ms(slot_ms(10) - 1_950);
        let skew = compare_slots(&clock, &status(6, 2), sent, received).expect("ahead");
        assert_eq!((skew.node_slot, skew.client_slot), (8, 9));
        assert!((skew.offset_bound + 10.0).abs() < 1e-9);
    }

    /// A boundary inside the round trip: the node read either slot, and
    /// neither is a disagreement.
    #[test]
    fn a_boundary_inside_the_round_trip_is_not_a_disagreement() {
        let clock = clock();
        let sent = at_ms(slot_ms(10) - 20);
        let received = at_ms(slot_ms(10) + 20);
        for node_slot in [9, 10] {
            let answer = status(node_slot - 1, 1);
            assert_eq!(compare_slots(&clock, &answer, sent, received), None);
        }
        assert_eq!(
            compare_slots(&clock, &status(11, 1), sent, received).map(|skew| skew.node_slot),
            Some(12)
        );
    }

    /// A distance of zero, or one a syncing node reports, is not read as the
    /// node's clock: a node that measures it against its peers (Teku) would
    /// otherwise put this client ahead on every missed slot.
    #[test]
    fn a_zero_distance_or_a_syncing_nodes_is_not_its_clock() {
        let clock = clock();
        let sent = at_ms(slot_ms(10) - 2_000);
        let received = at_ms(slot_ms(10) - 1_950);
        assert_eq!(compare_slots(&clock, &status(7, 0), sent, received), None);
        let syncing = SyncStatus {
            is_syncing: true,
            ..status(5, 2)
        };
        assert_eq!(compare_slots(&clock, &syncing, sent, received), None);
        let no_head = SyncStatus {
            head_slot: None,
            ..status(5, 2)
        };
        assert_eq!(compare_slots(&clock, &no_head, sent, received), None);
    }

    /// With no `Date` yet, a slot comparison that shows the clocks apart sets
    /// the offset to its bound and flags the node.
    #[test]
    fn a_slot_disagreement_flags_the_node_before_any_date_estimate() {
        let mut watch = ClockWatch::new(clock());
        watch.nodes.resize_with(1, NodeClock::default);
        let mut ahead = probe(10, 0, 0);
        ahead.outcome = Ok(status(12, 0));
        let reading = watch.read(0, 10, Some(&ahead)).expect("answered");
        assert!(reading.is_skewed());
        assert_eq!(reading.date_offset, None);
        assert_eq!(
            Some(reading.offset),
            reading.slots.map(|skew| skew.offset_bound)
        );
    }

    /// A `Date` that says the clocks agree, as a reverse proxy writing its own
    /// would, does not hide a node whose wall slot is behind this client's:
    /// the offset is held to what the slots prove.
    #[test]
    fn the_slots_hold_a_date_estimate_that_contradicts_them() {
        let mut watch = ClockWatch::new(clock());
        watch.nodes.resize_with(1, NodeClock::default);
        let mut reading = None;
        for slot in 10..13 {
            let behind = Probe {
                outcome: Ok(status(slot - 3, 1)),
                ..probe(slot, 0, 0)
            };
            reading = watch.read(0, slot, Some(&behind));
        }
        let reading = reading.expect("answered");
        let estimate = reading.date_offset.expect("three samples");
        assert!(estimate.abs() < 1.0, "{estimate}");
        let skew = reading.slots.expect("the slots disagree");
        assert!(!skew.client_is_behind());
        assert!(reading.is_skewed());
        assert_eq!(reading.offset, skew.offset_bound);
        assert!(reading.offset <= -10.0, "{}", reading.offset);
    }

    /// The issue's slot-level case through the probe itself: a node whose
    /// head is two slots past this client's clock is flagged; one slot past
    /// is not, whichever side of a boundary the probe lands on.
    #[tokio::test]
    async fn a_probed_head_two_slots_ahead_is_flagged_and_one_slot_is_not() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("after 1970")
            .as_secs();
        let clock = SlotClock::new(now - 1_000_000, SLOT_MS, 3_333, 6_667);
        for (ahead, flagged) in [(3, true), (1, false)] {
            let node = MockBeaconNode::new();
            let current = clock.now().expect("after genesis");
            node.set_sync_status(SyncStatus {
                head_slot: Some(current + ahead),
                ..status(0, 0)
            });
            let fallback = Arc::new(FallbackBeaconNode::new(vec![node]));
            fallback.probe(7, Duration::from_secs(1)).await;

            let mut watch = ClockWatch::new(clock.clone());
            let probes = fallback.health().snapshot();
            watch.observe(7, &probes);
            let reading = watch.read(0, 7, probes[0].as_ref()).expect("answered");
            assert_eq!(
                reading.is_skewed(),
                flagged,
                "{ahead} slots ahead: {reading:?}"
            );
        }
    }

    /// A probe keeps when each answer came back, and none for a node that did
    /// not answer.
    #[tokio::test]
    async fn a_probe_records_when_each_answer_came_back() {
        let fallback =
            FallbackBeaconNode::new(vec![MockBeaconNode::new(), MockBeaconNode::failing("down")]);
        fallback.probe(3, Duration::from_secs(1)).await;
        let snapshot = fallback.health().snapshot();
        let answered = snapshot[0].as_ref().expect("probed");
        let reply = answered.reply.expect("answered");
        assert!(reply.received >= answered.at);
        assert_eq!(reply.date, None, "a mock sends no Date");
        assert_eq!(snapshot[1].as_ref().expect("probed").reply, None);
    }

    /// One warning an epoch while the clocks disagree, and one line when they
    /// agree again; a flicker around the threshold does not log every slot.
    #[test]
    fn a_lasting_skew_is_warned_about_once_an_epoch() {
        let epoch = slots_per_epoch();
        let mut node = NodeClock::default();
        assert_eq!(node.report(100, false), Report::Quiet);
        assert_eq!(node.report(101, true), Report::Warn);
        assert_eq!(node.report(102, true), Report::Quiet);
        assert_eq!(node.report(103, false), Report::Agree);
        assert_eq!(node.report(104, true), Report::Quiet);
        assert_eq!(node.report(105, false), Report::Quiet);
        assert_eq!(node.report(101 + epoch - 1, true), Report::Quiet);
        assert_eq!(node.report(101 + epoch, true), Report::Warn);
    }

    fn passes(
        watch: &mut StepWatch,
        served: Slot,
        wall_ms: u64,
        mono: Instant,
    ) -> Option<Discontinuity> {
        watch.observe(&clock(), Some(served), at_ms(wall_ms), mono)
    }

    /// An ordinary pass: both clocks move a slot.
    #[test]
    fn an_ordinary_pass_is_no_discontinuity() {
        let mut watch = StepWatch::default();
        let start = Instant::now();
        assert_eq!(
            watch.observe(&clock(), None, at_ms(slot_ms(10) + 9_000), start),
            None
        );
        let next = start + Duration::from_millis(SLOT_MS);
        assert_eq!(passes(&mut watch, 10, slot_ms(11) + 9_000, next), None);
    }

    /// A step back of ten minutes lands the wall clock well before the slot
    /// just served: a backward step.
    #[test]
    fn a_backward_step_is_detected() {
        let mut watch = StepWatch::default();
        let start = Instant::now();
        passes(&mut watch, 99, slot_ms(100) + 9_000, start);
        let later = start + Duration::from_millis(SLOT_MS);
        let found = passes(&mut watch, 100, slot_ms(101) + 9_000 - 600_000, later);
        let Some(Discontinuity::Step {
            seconds,
            served,
            wall_slot,
        }) = found
        else {
            panic!("a step: {found:?}");
        };
        assert!((seconds + 600.0).abs() < 1e-6, "{seconds}");
        assert_eq!(served, 100);
        assert_eq!(wall_slot, Some(101 - 50));
    }

    /// A step forward of three slots, the monotonic clock having moved one:
    /// a forward step, as a host suspended with the process would show.
    #[test]
    fn a_multi_slot_forward_step_is_detected() {
        let mut watch = StepWatch::default();
        let start = Instant::now();
        passes(&mut watch, 9, slot_ms(10) + 9_000, start);
        let later = start + Duration::from_millis(SLOT_MS);
        let found = passes(&mut watch, 10, slot_ms(14) + 9_000, later);
        let Some(Discontinuity::Step { seconds, .. }) = found else {
            panic!("a step: {found:?}");
        };
        assert!((seconds - 36.0).abs() < 1e-6, "{seconds}");
    }

    /// Three slots of an overrun, the two clocks moving together: the loop
    /// was held up, which is not a step.
    #[test]
    fn an_overrun_is_a_stall_not_a_step() {
        let mut watch = StepWatch::default();
        let start = Instant::now();
        passes(&mut watch, 9, slot_ms(10) + 9_000, start);
        let later = start + Duration::from_millis(4 * SLOT_MS);
        assert_eq!(
            passes(&mut watch, 10, slot_ms(14) + 9_000, later),
            Some(Discontinuity::Stalled {
                served: 10,
                wall_slot: 14
            })
        );
    }

    /// A wall clock a few milliseconds behind the monotonic one, as a slew
    /// leaves it, just before the boundary of the slot served: no step,
    /// though it reads the slot before.
    #[test]
    fn a_slew_across_a_boundary_is_not_a_step() {
        let mut watch = StepWatch::default();
        let start = Instant::now();
        passes(&mut watch, 9, slot_ms(9) + 9_000, start);
        let later = start + Duration::from_millis(3_005);
        assert_eq!(passes(&mut watch, 10, slot_ms(10) - 1, later), None);
    }
}
