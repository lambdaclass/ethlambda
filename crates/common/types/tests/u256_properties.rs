//! Property tests for the beacon `U256`, whose ordering, decimal printing and
//! decimal parsing are all written by hand over its 32 little-endian bytes
//! (a derived `Ord` would compare the least significant byte first and
//! silently invert `terminal_total_difficulty` comparisons).
//!
//! The reference model is the value as two `u128` halves, compared and
//! printed with the standard library's own integer code where it fits.
//! Driven by ephyra; see `docs/property_testing.md`.

use std::cmp::Ordering;

use ephyra::prelude::*;
use ephyra::{BoxGen, gens};
use ethlambda_types::beacon::primitives::{ParseU256Error, U256};

/// `(high, low)` halves of the value.
fn halves(value: &U256) -> (u128, u128) {
    let low = u128::from_le_bytes(value.0[..16].try_into().unwrap());
    let high = u128::from_le_bytes(value.0[16..].try_into().unwrap());
    (high, low)
}

fn from_halves(high: u128, low: u128) -> U256 {
    let mut bytes = [0; 32];
    bytes[..16].copy_from_slice(&low.to_le_bytes());
    bytes[16..].copy_from_slice(&high.to_le_bytes());
    U256(bytes)
}

/// Values of every magnitude: zero, `u64`/`u128`-sized, just across the
/// 128-bit halves, full width, and next to `U256::MAX`.
fn u256s() -> BoxGen<U256> {
    let half = || {
        gens::frequency(vec![
            (3, gens::int(0u64..=u64::MAX).map(u128::from).boxed()),
            (
                2,
                gens::pick_from(vec![
                    0,
                    1,
                    9,
                    10,
                    u128::from(u64::MAX),
                    u128::MAX - 1,
                    u128::MAX,
                ])
                .boxed(),
            ),
            (
                2,
                (gens::int(..), gens::int(..))
                    .map(|(a, b): (u64, u64)| (u128::from(a) << 64) | u128::from(b))
                    .boxed(),
            ),
        ])
    };
    (
        gens::frequency(vec![
            (2, gens::constant(0u128).boxed()),
            (1, half().boxed()),
        ]),
        half(),
    )
        .map(|(high, low)| from_halves(high, low))
        .boxed()
}

/// Two values, the second often a one-byte edit of the first, so pairs that
/// agree on every byte but one (where a byte-order mistake shows) are common.
fn u256_pairs() -> BoxGen<(U256, U256)> {
    gens::dependent(
        (
            u256s(),
            gens::int(0usize..=31),
            gens::int(0u8..=255),
            gens::bool_with(0.7),
        ),
        |_| u256s(),
    )
    .map(|((a, at, byte, edit), other)| {
        let b = if edit {
            let mut b = a;
            b.0[at] = byte;
            b
        } else {
            other
        };
        (a, b)
    })
    .boxed()
}

#[ephyra::test]
fn ordering_is_numeric(#[ephyra(gen = u256_pairs())] pair: (U256, U256)) {
    let (a, b) = pair;
    assert_eq!(a.cmp(&b), halves(&a).cmp(&halves(&b)), "{a} vs {b}");
    assert_eq!(a.partial_cmp(&b), Some(a.cmp(&b)));
    assert_eq!(a == b, a.cmp(&b) == Ordering::Equal);
}

#[ephyra::test]
fn decimal_reads_back(#[ephyra(gen = u256s())] value: U256) {
    let text = value.to_string();
    assert_eq!(U256::from_dec_str(&text), Ok(value), "{text}");
    assert_eq!(value.to_decimal_string(), text);
    assert!(
        text == "0" || !text.starts_with('0'),
        "leading zero in {text}"
    );
}

#[ephyra::test]
fn decimal_matches_u128_where_it_fits(#[ephyra(gen = u256s())] value: U256) {
    let (high, low) = halves(&value);
    if high == 0 {
        assert_eq!(value.to_string(), low.to_string());
        assert_eq!(format!("{value:x}"), format!("{low:x}"));
        assert_eq!(value, U256::from_u128(low));
    }
}

#[ephyra::test]
fn json_reads_back(#[ephyra(gen = u256s())] value: U256) {
    let json = serde_json::to_string(&value).unwrap();
    assert_eq!(json, format!("\"{value}\""));
    assert_eq!(serde_json::from_str::<U256>(&json).unwrap(), value);
}

/// Decimal strings past `2^256 - 1` overflow rather than wrapping, at every
/// distance past it.
#[ephyra::test]
fn decimal_past_the_maximum_is_refused(
    #[ephyra(gen = gens::vec(gens::int(0u8..=9)).len(1..=6))] extra_digits: Vec<u8>,
    #[ephyra(gen = gens::int(1u8..=9))] bump: u8,
) {
    // 2^256 - 1 is 78 digits. Adding to its last digit, or appending more
    // digits, both make a larger number.
    let max = U256::MAX.to_string();
    assert_eq!(max.len(), 78);

    let mut appended = max.clone();
    appended.extend(extra_digits.iter().map(|d| char::from(b'0' + d)));
    assert_eq!(
        U256::from_dec_str(&appended),
        Err(ParseU256Error::Overflow),
        "{appended}"
    );

    // `...935` is the last three digits of the maximum; 5 + bump >= 6 > 5.
    assert!(max.ends_with('5'));
    let mut bumped = max[..77].to_string();
    let last = 5 + bump;
    if last < 10 {
        bumped.push(char::from(b'0' + last));
        assert_eq!(
            U256::from_dec_str(&bumped),
            Err(ParseU256Error::Overflow),
            "{bumped}"
        );
    }
}
