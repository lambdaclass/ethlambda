//! Choosing between the local payload and a builder's.

/// beacon-APIs' default `builder_boost_factor`: compare the two as they are.
pub(crate) const DEFAULT_BOOST_FACTOR: u64 = 100;

/// Where the block's payload comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Source {
    Local,
    Builder,
}

impl Source {
    /// The metric label.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Builder => "builder",
        }
    }
}

/// The local payload's side of the comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LocalOffer {
    /// What it pays, in wei.
    pub(crate) value: u128,
    /// The execution client wants it built locally whatever a bid pays.
    pub(crate) should_override_builder: bool,
}

/// Which payload the block carries, or `None` when neither is usable.
///
/// beacon-APIs' `builder_boost_factor`, a percentage: the local payload wins
/// iff `local >= factor * bid / 100`, multiplied first and rounded down once
/// (see [`boosted`]). So 100 compares the two exactly as they are, 0 always
/// keeps the local payload, and a tie goes local. A factor of `u64::MAX`
/// always takes the builder, except that the execution client's
/// `shouldOverrideBuilder` still wins. When one side failed, the other stands.
///
/// A bid that pays nothing never beats a local payload, whatever the factor:
/// it stands only in for one that failed, here or when its block fails to
/// assemble.
pub(crate) fn choose(
    local: Option<LocalOffer>,
    bid_value: Option<u128>,
    boost_factor: u64,
) -> Option<Source> {
    match (local, bid_value) {
        (None, None) => None,
        (Some(_), None) => Some(Source::Local),
        (None, Some(_)) => Some(Source::Builder),
        (Some(_), Some(0)) => Some(Source::Local),
        (Some(local), Some(_)) if local.should_override_builder => Some(Source::Local),
        (Some(_), Some(_)) if boost_factor == u64::MAX => Some(Source::Builder),
        (Some(local), Some(bid)) => Some(if local.value >= boosted(bid, boost_factor) {
            Source::Local
        } else {
            Source::Builder
        }),
    }
}

/// `factor * bid / 100`, rounded down once, at the end, and saturating at
/// `u128::MAX` as beacon-APIs asks of a large factor.
///
/// The spec's text divides first, `factor * (bid / 100)`, which rounds the bid
/// down to a multiple of 100 wei before scaling it: even at the default factor
/// of 100, a bid up to 99 wei better than the local payload lost to it.
/// Multiplying first is exact. The product is split as
/// `factor * (bid / 100) + factor * (bid % 100) / 100`, which is the same
/// number since the first term is a whole multiple of 100, so no type wider
/// than `u128` is needed: the second term is below `factor`, and only the
/// first can overflow.
fn boosted(bid: u128, factor: u64) -> u128 {
    let factor = u128::from(factor);
    let whole = factor.saturating_mul(bid / 100);
    let rest = factor * (bid % 100) / 100;
    whole.saturating_add(rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ETH: u128 = 1_000_000_000_000_000_000;

    fn local(value: u128) -> Option<LocalOffer> {
        Some(LocalOffer {
            value,
            should_override_builder: false,
        })
    }

    #[test]
    fn the_selection_table() {
        let overriding = Some(LocalOffer {
            value: 1,
            should_override_builder: true,
        });
        let cases = [
            ("neither", None, None, 100, None),
            ("local only", local(1), None, 100, Some(Source::Local)),
            ("bid only", None, Some(ETH), 100, Some(Source::Builder)),
            (
                "bid pays more",
                local(ETH),
                Some(2 * ETH),
                100,
                Some(Source::Builder),
            ),
            (
                "local pays more",
                local(2 * ETH),
                Some(ETH),
                100,
                Some(Source::Local),
            ),
            (
                "a tie goes local",
                local(ETH),
                Some(ETH),
                100,
                Some(Source::Local),
            ),
            (
                "one wei more wins at 100",
                local(ETH),
                Some(ETH + 1),
                100,
                Some(Source::Builder),
            ),
            (
                "rounded once, after scaling",
                // 50 * 3 / 100 is 1; 50 * (3 / 100) would be 0.
                local(0),
                Some(3),
                50,
                Some(Source::Builder),
            ),
            (
                "factor 0 keeps local",
                local(1),
                Some(100 * ETH),
                0,
                Some(Source::Local),
            ),
            (
                "factor 50 halves the bid",
                local(ETH),
                Some(2 * ETH),
                50,
                Some(Source::Local),
            ),
            (
                "factor 200 doubles it",
                local(ETH + 1),
                Some(ETH),
                200,
                Some(Source::Builder),
            ),
            (
                "u64::MAX takes the bid",
                local(100 * ETH),
                Some(1),
                u64::MAX,
                Some(Source::Builder),
            ),
            (
                "the override keeps local",
                overriding,
                Some(100 * ETH),
                u64::MAX,
                Some(Source::Local),
            ),
            (
                "a bid paying nothing loses to local",
                local(0),
                Some(0),
                100,
                Some(Source::Local),
            ),
            (
                "even under u64::MAX",
                local(1),
                Some(0),
                u64::MAX,
                Some(Source::Local),
            ),
            (
                "a bid paying nothing stands in for no local",
                None,
                Some(0),
                0,
                Some(Source::Builder),
            ),
        ];
        for (name, local, bid, factor, expected) in cases {
            assert_eq!(choose(local, bid, factor), expected, "{name}");
        }
    }

    /// `factor * bid / 100` rounded down once, checked against the product
    /// itself wherever it fits in a `u128`.
    #[test]
    fn the_bid_is_scaled_before_it_is_rounded() {
        let bids = [
            0,
            1,
            99,
            100,
            101,
            12_345,
            ETH - 1,
            ETH + 99,
            u128::from(u64::MAX),
        ];
        let factors = [0, 1, 50, 99, 100, 101, 150, 200, 1_000_000, u64::MAX - 1];
        for bid in bids {
            for factor in factors {
                let exact = u128::from(factor) * bid / 100;
                assert_eq!(boosted(bid, factor), exact, "{factor} * {bid} / 100");
            }
        }
    }

    #[test]
    fn a_product_past_u128_saturates() {
        assert_eq!(boosted(u128::MAX, 200), u128::MAX);
        assert_eq!(boosted(u128::MAX / 2, u64::MAX - 1), u128::MAX);
    }
}
