//! The specification's math helpers.

use crate::constants::{UINT64_MAX, UINT64_MAX_SQRT};
use crate::primitives::{Bytes32, H256};

/// The largest integer `x` such that `x * x <= n`.
///
/// Newton's method, as the specification writes it. The maximum input is special
/// cased because the general algorithm's first step would overflow on it.
pub fn integer_squareroot(n: u64) -> u64 {
    if n == UINT64_MAX {
        return UINT64_MAX_SQRT;
    }
    let mut x = n;
    let mut y = x.div_ceil(2);
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

/// The exclusive-or of two 32-byte strings.
pub fn xor(a: Bytes32, b: Bytes32) -> Bytes32 {
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = a.0[index] ^ b.0[index];
    }
    H256(out)
}

/// Interprets up to eight bytes as a little-endian integer, which is the
/// specification's `bytes_to_uint64`.
///
/// Shorter input is zero-extended rather than rejected, since the specification
/// applies this to hash prefixes of a fixed width.
pub fn bytes_to_uint64(data: &[u8]) -> u64 {
    let mut buffer = [0u8; 8];
    let take = data.len().min(8);
    buffer[..take].copy_from_slice(&data[..take]);
    u64::from_le_bytes(buffer)
}

/// `a - b`, saturating at zero.
///
/// The specification names this because Python integers do not wrap, so a
/// subtraction that would go negative has to be written explicitly. Rust's
/// `saturating_sub` is the same operation, and this exists so call sites can read
/// like the spec.
pub fn saturating_sub(a: u64, b: u64) -> u64 {
    a.saturating_sub(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_squareroot_matches_the_definition() {
        for n in 0u64..100 {
            let root = integer_squareroot(n);
            assert!(root * root <= n, "{root}^2 should be at most {n}");
            assert!(
                (root + 1) * (root + 1) > n,
                "{root} should be the largest such integer for {n}"
            );
        }
        assert_eq!(integer_squareroot(0), 0);
        assert_eq!(integer_squareroot(1), 1);
        assert_eq!(integer_squareroot(u64::MAX), UINT64_MAX_SQRT);
    }

    #[test]
    fn integer_squareroot_handles_perfect_squares_and_their_neighbours() {
        // The loop's exit condition is where an off-by-one would hide, so check
        // either side of a boundary.
        assert_eq!(integer_squareroot(15), 3);
        assert_eq!(integer_squareroot(16), 4);
        assert_eq!(integer_squareroot(17), 4);
    }

    #[test]
    fn xor_is_its_own_inverse() {
        let a = Bytes32::repeat_byte(0xa5);
        let b = Bytes32::repeat_byte(0x3c);
        assert_eq!(xor(xor(a, b), b), a);
    }

    #[test]
    fn bytes_to_uint64_is_little_endian_and_zero_extends() {
        assert_eq!(bytes_to_uint64(&[1, 0, 0, 0, 0, 0, 0, 0]), 1);
        assert_eq!(bytes_to_uint64(&[0, 1]), 256);
        assert_eq!(bytes_to_uint64(&[0xff; 8]), u64::MAX);
    }
}
