//! Choosing between this node's own build and a pooled builder bid for
//! `produceBlockV4`. Pure: no store, no clock.
//!
//! Units differ on the two sides: a bid's value is in Gwei and the execution
//! client's `blockValue` in Wei, and the specification weights the local value
//! by 100 against a bid weighted by `builder_boost_factor`. Everything that
//! compares the two goes through [`choose_payload`], so the conversion lives in
//! one place.

use ethlambda_types::beacon::containers::gloas::{ExecutionPayloadBid, SignedExecutionPayloadBid};
use ethlambda_types::beacon::primitives::Uint256;

/// Dividing a wei amount by this yields the amount in Gwei times 100, the
/// local value's weight: `wei / 1e9 * 100 == wei / 1e7`.
const WEI_PER_WEIGHTED_GWEI: u128 = 10_000_000;

/// The local build, as the choice sees it.
pub(crate) struct LocalCandidate {
    pub(crate) value_wei: u128,
    /// The execution client's `shouldOverrideBuilder`.
    pub(crate) should_override_builder: bool,
}

// The enum is short-lived (one per block production), so boxing the bid buys
// nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PayloadChoice {
    Local,
    Bid(SignedExecutionPayloadBid),
}

/// `value.saturating_add(execution_payment)`; a p2p bid's payment is zero.
pub(crate) fn bid_total_gwei(bid: &ExecutionPayloadBid) -> u64 {
    bid.value.saturating_add(bid.execution_payment)
}

/// Saturating conversion of a wei amount: the 32 little-endian bytes of a
/// `uint256` clamped to `u128::MAX`.
pub(crate) fn wei_u128(value: &Uint256) -> u128 {
    let (low, high) = value.0.split_at(16);
    if high.iter().any(|byte| *byte != 0) {
        return u128::MAX;
    }
    u128::from_le_bytes(low.try_into().expect("sixteen bytes"))
}

/// The bid to build on, or the local build.
///
/// 1. The best bid is the first of `bids_desc` (value descending) whose total
///    is at least `min_bid`.
/// 2. With no local build, that bid, or `None` if there is none.
/// 3. A local build that asks to override builders wins.
/// 4. Otherwise the bid wins iff `builder_boost_factor * bid_gwei` exceeds the
///    local value in the same weighting: `factor * gwei * 1e9 > 100 * wei`,
///    which for integers is `factor * gwei > floor(wei / 1e7)`. The left side
///    is a product of two `u64`s, so it cannot overflow `u128`.
/// 5. The local build wins a tie, so a factor of `0` prefers it and `u64::MAX`
///    prefers the bid, each unless step 2 or 3 says otherwise.
pub(crate) fn choose_payload(
    local: Option<&LocalCandidate>,
    bids_desc: &[SignedExecutionPayloadBid],
    min_bid: u64,
    builder_boost_factor: u64,
) -> Option<PayloadChoice> {
    let best = bids_desc
        .iter()
        .find(|signed| bid_total_gwei(&signed.message) >= min_bid);
    let Some(local) = local else {
        return best.cloned().map(PayloadChoice::Bid);
    };
    let Some(best) = best else {
        return Some(PayloadChoice::Local);
    };
    if local.should_override_builder {
        return Some(PayloadChoice::Local);
    }
    let weighted_bid = u128::from(builder_boost_factor) * u128::from(bid_total_gwei(&best.message));
    let weighted_local = local.value_wei / WEI_PER_WEIGHTED_GWEI;
    if weighted_bid > weighted_local {
        Some(PayloadChoice::Bid(best.clone()))
    } else {
        Some(PayloadChoice::Local)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bid(builder: u64, value: u64) -> SignedExecutionPayloadBid {
        let mut signed = SignedExecutionPayloadBid::default();
        signed.message.builder_index = builder;
        signed.message.value = value;
        signed
    }

    fn local(value_wei: u128) -> LocalCandidate {
        LocalCandidate {
            value_wei,
            should_override_builder: false,
        }
    }

    fn picks_bid(choice: Option<PayloadChoice>) -> bool {
        matches!(choice, Some(PayloadChoice::Bid(_)))
    }

    #[test]
    fn a_tie_goes_to_the_local_build() {
        // 1e9 wei is 1 gwei; factor 100 weights both sides to 100.
        let bids = [bid(1, 1)];
        assert_eq!(
            choose_payload(Some(&local(1_000_000_000)), &bids, 0, 100),
            Some(PayloadChoice::Local)
        );
    }

    #[test]
    fn the_floor_at_ten_million_wei_decides_the_boundary() {
        let bids = [bid(1, 1)];
        // One wei short of the tie: the local weighted value floors to 99.
        assert!(picks_bid(choose_payload(
            Some(&local(999_999_999)),
            &bids,
            0,
            100
        )));
        // Exactly the tie, and above it.
        for wei in [1_000_000_000, 1_000_000_001, 1_000_000_000_000] {
            assert_eq!(
                choose_payload(Some(&local(wei)), &bids, 0, 100),
                Some(PayloadChoice::Local),
                "{wei}"
            );
        }
    }

    #[test]
    fn a_factor_of_zero_prefers_local_and_the_maximum_prefers_the_bid() {
        let bids = [bid(1, 5)];
        assert_eq!(
            choose_payload(Some(&local(1)), &bids, 0, 0),
            Some(PayloadChoice::Local)
        );
        assert!(picks_bid(choose_payload(
            Some(&local(1_000_000_000_000_000)),
            &bids,
            0,
            u64::MAX
        )));
    }

    #[test]
    fn a_factor_of_zero_still_takes_the_bid_when_the_local_build_failed() {
        let bids = [bid(1, 5)];
        assert!(picks_bid(choose_payload(None, &bids, 0, 0)));
    }

    #[test]
    fn the_min_bid_floor_skips_bids_below_it() {
        let bids = [bid(1, 9), bid(2, 5), bid(3, 1)];
        // The best bid is below the floor, and so are the rest.
        assert_eq!(
            choose_payload(Some(&local(0)), &bids, 10, u64::MAX),
            Some(PayloadChoice::Local)
        );
        assert_eq!(choose_payload(None, &bids, 10, u64::MAX), None);
        // The floor is inclusive.
        let Some(PayloadChoice::Bid(chosen)) = choose_payload(None, &bids, 9, 0) else {
            panic!("the bid at the floor is eligible")
        };
        assert_eq!(chosen.message.builder_index, 1);
    }

    #[test]
    fn the_override_flag_keeps_the_local_build() {
        let bids = [bid(1, u64::MAX)];
        let overriding = LocalCandidate {
            value_wei: 0,
            should_override_builder: true,
        };
        assert_eq!(
            choose_payload(Some(&overriding), &bids, 0, u64::MAX),
            Some(PayloadChoice::Local)
        );
    }

    #[test]
    fn no_local_build_and_no_bid_is_nothing() {
        assert_eq!(choose_payload(None, &[], 0, 100), None);
        assert_eq!(
            choose_payload(Some(&local(1)), &[], 0, 100),
            Some(PayloadChoice::Local)
        );
    }

    #[test]
    fn the_total_counts_execution_payment_and_saturates() {
        let mut signed = bid(1, u64::MAX);
        signed.message.execution_payment = 5;
        assert_eq!(bid_total_gwei(&signed.message), u64::MAX);
        signed.message.value = 3;
        assert_eq!(bid_total_gwei(&signed.message), 8);
    }

    #[test]
    fn the_weighted_comparison_cannot_overflow() {
        let bids = [bid(1, u64::MAX)];
        assert!(picks_bid(choose_payload(
            Some(&local(u128::MAX)),
            &bids,
            0,
            u64::MAX
        )));
    }

    #[test]
    fn wei_saturates_at_u128() {
        assert_eq!(wei_u128(&Uint256::from_u128(42)), 42);
        assert_eq!(wei_u128(&Uint256::from_u128(u128::MAX)), u128::MAX);
        assert_eq!(wei_u128(&Uint256::MAX), u128::MAX);
        let mut bytes = [0u8; 32];
        bytes[16] = 1;
        assert_eq!(
            wei_u128(&ethlambda_types::beacon::primitives::U256(bytes)),
            u128::MAX
        );
    }
}
