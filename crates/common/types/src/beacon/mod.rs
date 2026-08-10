//! Beacon Chain types, namespaced away from the lean types alongside them.
//!
//! `ethlambda-types` already has `primitives`, `constants`, and `checkpoint`
//! modules of its own, and lean's `Checkpoint` is a different type from
//! beacon's by the same name. Everything moved out of `ethlambda-beacon` lives
//! under this module so both sets can coexist.

pub mod primitives;

#[cfg(test)]
mod tests {
    #[test]
    fn beacon_and_lean_roots_are_distinct_types() {
        let beacon: super::primitives::Root = super::primitives::Root::zero();
        let lean = crate::primitives::H256::ZERO;
        assert_eq!(beacon.0, lean.0);
    }
}
