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
/// beacon-APIs' `builder_boost_factor`, taken literally: the local payload
/// wins iff `local >= factor * (bid / 100)`. So 100 compares the two as they
/// are, 0 always keeps the local payload, and a tie goes local.
/// A factor of `u64::MAX` always takes the builder, except that the execution
/// client's `shouldOverrideBuilder` still wins. When one side failed, the
/// other stands.
pub(crate) fn choose(
    local: Option<LocalOffer>,
    bid_value: Option<u128>,
    boost_factor: u64,
) -> Option<Source> {
    match (local, bid_value) {
        (None, None) => None,
        (Some(_), None) => Some(Source::Local),
        (None, Some(_)) => Some(Source::Builder),
        (Some(local), Some(_)) if local.should_override_builder => Some(Source::Local),
        (Some(_), Some(_)) if boost_factor == u64::MAX => Some(Source::Builder),
        (Some(local), Some(bid)) => {
            let boosted = u128::from(boost_factor).saturating_mul(bid / 100);
            Some(if local.value >= boosted {
                Source::Local
            } else {
                Source::Builder
            })
        }
    }
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
        ];
        for (name, local, bid, factor, expected) in cases {
            assert_eq!(choose(local, bid, factor), expected, "{name}");
        }
    }
}
