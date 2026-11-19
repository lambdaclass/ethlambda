//! Fork identity.
//!
//! The variant order is the fork order, so the derived [`Ord`] is the comparison
//! the state transition uses to gate behavior: `fork >= ForkName::Altair` reads
//! as "altair or later", matching how the specification introduces changes.

use core::fmt;

use crate::beacon::preset;

/// How many slots apart full state snapshots are written for lean, in
/// [`ForkName::snapshot_interval`].
///
/// A slot count, not a duration: the reconstruction walk costs the same per
/// slot whatever the configured cadence is. ~68 minutes at the default
/// 4-second slots.
///
/// Matches what `crates/storage/src/store.rs`'s `SNAPSHOT_ANCHOR_INTERVAL`
/// used before that value moved here, so lean's on-disk layout is unchanged.
/// Snapshots bound a diff-chain reconstruction walk to at most this many
/// steps.
const LEAN_SNAPSHOT_INTERVAL: u64 = 1_024;

/// How many slots apart full state snapshots are written for the Beacon
/// Chain, in [`ForkName::snapshot_interval`]: one epoch. A beacon read applies
/// one delta against its snapshot whatever the interval, so what this bounds
/// is how large a delta grows (it carries every change since its snapshot) and
/// how often a full snapshot is written.
fn beacon_snapshot_interval() -> u64 {
    preset::slots_per_epoch()
}

/// A named fork of the Beacon Chain, ordered oldest to newest, followed by
/// Lean.
///
/// The variant order is the fork order, so the derived [`Ord`] is the comparison
/// the state transition uses to gate behavior: `fork >= ForkName::Altair` reads
/// as "altair or later".
///
/// [`ForkName::Lean`] is last so that every such gate reads as true for a lean
/// state, and is deliberately absent from [`ForkName::ALL`]: lean is not a point
/// on the Beacon Chain's fork timeline, has no spec fixtures, and must never be
/// a target of the beacon STF's `upgrade`-style traversal. See
/// [`ForkName::ALL`].
///
/// [`ForkName::Eip8483`] and [`ForkName::Pq`] are consensus-specs feature
/// forks (`specs/_features/{eip8483,pq}` on the `pq` branch, pinned at
/// `a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c`), not mainnet upgrades: the
/// PQ fork replaces BLS with leanXMSS, and needs the EIP-8483 registrations
/// made before it, so the two are scheduled in that order after gloas. Other
/// forks after gloas exist upstream but are out of scope for this crate.
///
/// Each builds on the fork before it, as every fork here does: EIP-8483 is
/// gloas plus its two registration requests, and PQ is EIP-8483 with BLS
/// replaced. So a rule gated `fork >= ForkName::Gloas` holds at both, one
/// gated `>= ForkName::Eip8483` holds at PQ, and a rule a later fork replaces
/// is that fork's own match arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ForkName {
    Phase0,
    Altair,
    Bellatrix,
    Capella,
    Deneb,
    Electra,
    Fulu,
    Gloas,
    /// EIP-8483: validators and builders register post-quantum key material
    /// through execution-layer requests, which the PQ fork then adopts.
    Eip8483,
    /// The post-quantum fork: leanXMSS signatures replace BLS, sync
    /// committees are removed, and RANDAO reveals become VRF proofs.
    Pq,
    /// The Lean consensus protocol, which this repository implements alongside
    /// the Beacon Chain. Not a Beacon Chain fork, and not in [`ForkName::ALL`].
    Lean,
}

impl ForkName {
    /// Every *Beacon Chain* fork this crate implements, in order.
    ///
    /// [`ForkName::Lean`] is not here: it is not a Beacon Chain fork. Because
    /// `parse`, `previous`, `next`, and the spec-fixture harness all search this
    /// array, its absence is what makes `parse("lean")` return `None`, keeps
    /// `Gloas.next()` at `None`, and stops any fixture directory from resolving
    /// to a lean case.
    pub const ALL: [ForkName; 10] = [
        ForkName::Phase0,
        ForkName::Altair,
        ForkName::Bellatrix,
        ForkName::Capella,
        ForkName::Deneb,
        ForkName::Electra,
        ForkName::Fulu,
        ForkName::Gloas,
        ForkName::Eip8483,
        ForkName::Pq,
    ];

    /// The lowercase name the specification and its fixture paths use.
    pub fn as_str(self) -> &'static str {
        match self {
            ForkName::Phase0 => "phase0",
            ForkName::Altair => "altair",
            ForkName::Bellatrix => "bellatrix",
            ForkName::Capella => "capella",
            ForkName::Deneb => "deneb",
            ForkName::Electra => "electra",
            ForkName::Fulu => "fulu",
            ForkName::Gloas => "gloas",
            ForkName::Eip8483 => "eip8483",
            ForkName::Pq => "pq",
            ForkName::Lean => "lean",
        }
    }

    /// Parses a fork name as written in the specification and its fixture paths.
    ///
    /// Returns `None` for forks outside this crate's scope, which lets fixture
    /// runners skip unsupported directories rather than fail on them.
    pub fn parse(name: &str) -> Option<Self> {
        ForkName::ALL.into_iter().find(|f| f.as_str() == name)
    }

    /// The fork immediately before this one, or `None` for phase0.
    pub fn previous(self) -> Option<Self> {
        let index = ForkName::ALL.iter().position(|f| *f == self)?;
        index.checked_sub(1).map(|i| ForkName::ALL[i])
    }

    /// The fork immediately after this one, or `None` for the newest.
    pub fn next(self) -> Option<Self> {
        let index = ForkName::ALL.iter().position(|f| *f == self)?;
        ForkName::ALL.get(index + 1).copied()
    }

    /// Whether this node follows a chain that has reached this fork.
    ///
    /// Every beacon fork is followed. Gloas needs the payload envelopes and
    /// payload attestations that phase0 through fulu do not: the chain actor
    /// imports the envelopes, the network side delivers them and the two
    /// gloas gossip topics, and fork choice keeps the head's payload status.
    /// The question stays a function so a fork this node cannot follow has
    /// one place to say so; every site whose rule is "does this node follow
    /// the fork" calls it.
    ///
    /// # Panics
    ///
    /// On [`ForkName::Lean`], which is not a point on the beacon fork
    /// schedule.
    pub fn is_followed(self) -> bool {
        match self {
            ForkName::Phase0
            | ForkName::Altair
            | ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Deneb
            | ForkName::Electra
            | ForkName::Fulu
            | ForkName::Gloas
            // PQ: its blocks and envelopes are gossiped, requested and
            // imported like gloas's, its execution requests go to the engine
            // as gloas's do, and its attestation proofs need the prover
            // backend the network runs (`ethlambda_crypto::stark`). Run
            // against Lighthouse on a PQ-at-genesis devnet.
            | ForkName::Pq => true,
            // Not yet: its block's cheap gossip rules, its envelope topic's
            // decode and rules, and its fetched envelopes' checks still take
            // gloas's shapes. Nothing schedules it: the PQ devnet starts on PQ.
            ForkName::Eip8483 => false,
            ForkName::Lean => super::lean_fork_unreachable("ForkName::is_followed"),
        }
    }

    /// Whether blocks of this fork reveal their execution payload in a separate
    /// envelope (gloas, EIP-7732, and any fork after it).
    ///
    /// An explicit match rather than `self >= ForkName::Gloas`: the derived
    /// order puts [`ForkName::Lean`] after every beacon fork, so that
    /// comparison is true for lean, which has no envelopes. A fork added after
    /// gloas must be listed here, so the compiler forces the decision.
    pub const fn has_payload_envelopes(self) -> bool {
        match self {
            ForkName::Gloas | ForkName::Eip8483 | ForkName::Pq => true,
            ForkName::Phase0
            | ForkName::Altair
            | ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Deneb
            | ForkName::Electra
            | ForkName::Fulu
            | ForkName::Lean => false,
        }
    }

    /// The one-byte tag this fork is stored under in a `States` value.
    ///
    /// Spelled out rather than `self as u8`. The variant order is already
    /// load-bearing for the derived [`Ord`] (see this enum's own doc), so
    /// deriving the on-disk tag from it too would mean a reorder made for the
    /// ordering's sake silently reinterpreted every state already written.
    ///
    /// [`ForkName::Lean`] takes 255 rather than 8 so that the beacon forks after
    /// gloas can keep taking the next free value as they land.
    pub const fn selector(self) -> u8 {
        match self {
            ForkName::Phase0 => 0,
            ForkName::Altair => 1,
            ForkName::Bellatrix => 2,
            ForkName::Capella => 3,
            ForkName::Deneb => 4,
            ForkName::Electra => 5,
            ForkName::Fulu => 6,
            ForkName::Gloas => 7,
            ForkName::Eip8483 => 8,
            ForkName::Pq => 9,
            ForkName::Lean => 255,
        }
    }

    /// How many slots apart full state snapshots are written for this fork.
    ///
    /// A storage tuning parameter, not a consensus one, which is why it lives
    /// here rather than on `Config`: putting it in a config a chain agrees on
    /// would imply the two had to agree on it.
    ///
    /// Lean's interval does not survive contact with a ~350 MB beacon state:
    /// a beacon diff carries every change since its snapshot, so a long
    /// interval lets deltas grow large, and a snapshot is a full copy of the
    /// state. Beacon takes an epoch, which bounds both; a read applies a single
    /// delta whatever the interval, and decodes once.
    pub fn snapshot_interval(self) -> u64 {
        match self {
            ForkName::Lean => LEAN_SNAPSHOT_INTERVAL,
            ForkName::Phase0
            | ForkName::Altair
            | ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Deneb
            | ForkName::Electra
            | ForkName::Fulu
            | ForkName::Gloas
            | ForkName::Eip8483
            | ForkName::Pq => beacon_snapshot_interval(),
        }
    }

    /// The inverse of [`ForkName::selector`].
    ///
    /// `None` for a byte this build does not know, which means a corrupt or
    /// future-format database rather than anything a caller can recover from.
    pub const fn from_selector(byte: u8) -> Option<ForkName> {
        match byte {
            0 => Some(ForkName::Phase0),
            1 => Some(ForkName::Altair),
            2 => Some(ForkName::Bellatrix),
            3 => Some(ForkName::Capella),
            4 => Some(ForkName::Deneb),
            5 => Some(ForkName::Electra),
            6 => Some(ForkName::Fulu),
            7 => Some(ForkName::Gloas),
            8 => Some(ForkName::Eip8483),
            9 => Some(ForkName::Pq),
            255 => Some(ForkName::Lean),
            _ => None,
        }
    }
}

impl fmt::Display for ForkName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_follows_fork_order() {
        assert!(ForkName::Phase0 < ForkName::Altair);
        assert!(ForkName::Deneb < ForkName::Electra);
        assert!(ForkName::Fulu > ForkName::Phase0);
    }

    #[test]
    fn only_gloas_and_later_beacon_forks_have_payload_envelopes() {
        for fork in ForkName::ALL {
            assert_eq!(fork.has_payload_envelopes(), fork >= ForkName::Gloas);
        }
        assert!(!ForkName::Lean.has_payload_envelopes());
    }

    #[test]
    fn parse_round_trips_every_fork() {
        for fork in ForkName::ALL {
            assert_eq!(ForkName::parse(fork.as_str()), Some(fork));
        }
        assert_eq!(ForkName::parse("gloas"), Some(ForkName::Gloas));
        assert_eq!(ForkName::parse("heze"), None);
    }

    #[test]
    fn pq_is_the_last_beacon_fork() {
        assert_eq!(ForkName::Fulu.next(), Some(ForkName::Gloas));
        assert_eq!(ForkName::Gloas.next(), Some(ForkName::Eip8483));
        assert_eq!(ForkName::Eip8483.next(), Some(ForkName::Pq));
        // Also guards the reason Lean is kept out of ALL: adding it there
        // would make this None into Some(Lean) and let `upgrade` walk off
        // the end.
        assert_eq!(ForkName::Pq.next(), None);
    }

    #[test]
    fn neighbours_terminate_at_the_ends() {
        assert_eq!(ForkName::Phase0.previous(), None);
        assert_eq!(ForkName::Pq.next(), None);
        assert_eq!(ForkName::Altair.previous(), Some(ForkName::Phase0));
        assert_eq!(ForkName::Altair.next(), Some(ForkName::Bellatrix));
    }

    #[test]
    fn lean_sorts_after_every_beacon_fork() {
        // "Lean is the next fork": every `fork >= ForkName::X` gate in the
        // state transition reads as true for a lean state.
        for fork in ForkName::ALL {
            assert!(ForkName::Lean > fork, "Lean must outrank {fork}");
        }
    }

    #[test]
    fn lean_is_not_a_beacon_fork() {
        // ALL drives `parse`, `previous`, `next`, and the fixture harness's
        // test-list construction. Lean is outside all four.
        assert!(!ForkName::ALL.contains(&ForkName::Lean));
        assert_eq!(ForkName::parse("lean"), None);
        assert_eq!(ForkName::Lean.next(), None);
        assert_eq!(ForkName::Lean.previous(), None);
    }

    #[test]
    fn lean_has_a_name() {
        assert_eq!(ForkName::Lean.as_str(), "lean");
    }

    #[test]
    fn every_fork_round_trips_through_its_selector() {
        for fork in ForkName::ALL {
            assert_eq!(ForkName::from_selector(fork.selector()), Some(fork));
        }
        // Lean is outside ALL but is exactly the value the tag exists to
        // distinguish, so it is checked separately rather than left out.
        assert_eq!(
            ForkName::from_selector(ForkName::Lean.selector()),
            Some(ForkName::Lean)
        );
    }

    #[test]
    fn the_snapshot_interval_is_per_chain() {
        // Lean's interval must match what the storage layer used before this
        // was factored out, or lean's on-disk layout silently changes.
        assert_eq!(ForkName::Lean.snapshot_interval(), LEAN_SNAPSHOT_INTERVAL);
        assert_eq!(
            ForkName::Electra.snapshot_interval(),
            beacon_snapshot_interval()
        );
        assert_ne!(
            ForkName::Lean.snapshot_interval(),
            ForkName::Electra.snapshot_interval()
        );
    }

    #[test]
    fn every_beacon_fork_but_eip8483_is_followed() {
        for fork in ForkName::ALL {
            assert_eq!(fork.is_followed(), fork != ForkName::Eip8483, "{fork:?}");
        }
    }

    #[test]
    #[should_panic(expected = "ForkName::Lean reached a Beacon Chain function")]
    fn lean_is_not_a_fork_the_node_can_follow() {
        ForkName::Lean.is_followed();
    }

    #[test]
    fn selectors_are_pinned_to_their_on_disk_values() {
        // These bytes are a storage format: changing one makes every existing
        // database decode as the wrong fork. Asserted literally rather than
        // derived from the variant order, which the derived Ord already owns.
        assert_eq!(ForkName::Phase0.selector(), 0);
        assert_eq!(ForkName::Fulu.selector(), 6);
        assert_eq!(ForkName::Gloas.selector(), 7);
        assert_eq!(ForkName::Eip8483.selector(), 8);
        assert_eq!(ForkName::Pq.selector(), 9);
        // Lean sits at the top of the byte range so heze can keep taking the
        // next free value after gloas.
        assert_eq!(ForkName::Lean.selector(), 255);
        assert_eq!(ForkName::from_selector(10), None);
    }
}
