//! Fork identity.
//!
//! The variant order is the fork order, so the derived [`Ord`] is the comparison
//! the state transition uses to gate behavior: `fork >= ForkName::Altair` reads
//! as "altair or later", matching how the specification introduces changes.

use core::fmt;

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
/// a target of `ethlambda_beacon::upgrade`-style traversal. See
/// [`ForkName::ALL`].
///
/// Forks after fulu exist upstream but are out of scope for this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ForkName {
    Phase0,
    Altair,
    Bellatrix,
    Capella,
    Deneb,
    Electra,
    Fulu,
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
    /// `Fulu.next()` at `None`, and stops any fixture directory from resolving
    /// to a lean case.
    pub const ALL: [ForkName; 7] = [
        ForkName::Phase0,
        ForkName::Altair,
        ForkName::Bellatrix,
        ForkName::Capella,
        ForkName::Deneb,
        ForkName::Electra,
        ForkName::Fulu,
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
    fn parse_round_trips_every_fork() {
        for fork in ForkName::ALL {
            assert_eq!(ForkName::parse(fork.as_str()), Some(fork));
        }
        assert_eq!(ForkName::parse("gloas"), None);
    }

    #[test]
    fn neighbours_terminate_at_the_ends() {
        assert_eq!(ForkName::Phase0.previous(), None);
        assert_eq!(ForkName::Fulu.next(), None);
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
    fn fulu_is_still_the_last_beacon_fork() {
        // Guards the reason Lean is kept out of ALL: adding it there would make
        // this None into Some(Lean) and let `upgrade` walk off the end.
        assert_eq!(ForkName::Fulu.next(), None);
    }

    #[test]
    fn lean_has_a_name() {
        assert_eq!(ForkName::Lean.as_str(), "lean");
    }
}
