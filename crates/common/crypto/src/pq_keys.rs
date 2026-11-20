//! A validator's PQ-fork key material, derived from its BLS signing key the
//! way ethPandaOps' PQ genesis tooling (eth-beacon-genesis) and Lighthouse's
//! PQ branch derive it, so a validator's keystore is all it needs on a
//! network whose genesis that tooling built:
//!
//! - the leanXMSS key grows from `sha256("leanxmss-seed" || sk)`;
//! - the VRF seed is `sha256("vrf-seed" || sk)`.
//!
//! `sk` is the 32-byte big-endian BLS secret key a keystore holds. The
//! specification leaves both seeds to the validator (`pq/validator.md`,
//! "XMSS public key" and "VRF tree"), asking only that they be independent
//! secrets; deriving them from the signing key is the devnet's convention,
//! not the specification's.
//!
//! What grows from the VRF seed is the specification's own: the tree
//! `compute_vrf_root` defines, in [`crate::vrf`].

use sha2::{Digest, Sha256};

use crate::{lean_xmss, vrf};

fn sha256_concat(prefix: &[u8], body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(prefix);
    hasher.update(body);
    hasher.finalize().into()
}

/// The seed a validator's leanXMSS key grows from.
pub fn xmss_seed(bls_secret_key: &[u8; 32]) -> lean_xmss::Seed {
    sha256_concat(b"leanxmss-seed", bls_secret_key)
}

/// A validator's VRF seed, the specification's `vrf_seed`.
pub fn vrf_seed(bls_secret_key: &[u8; 32]) -> vrf::Node {
    sha256_concat(b"vrf-seed", bls_secret_key)
}

/// A validator's leanXMSS key. Generating it builds the key's whole top tree:
/// about a second and a half across cores.
pub fn xmss_key(bls_secret_key: &[u8; 32]) -> lean_xmss::SecretKey {
    lean_xmss::key_gen(&xmss_seed(bls_secret_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(text: &str) -> [u8; 32] {
        hex::decode(text.trim_start_matches("0x"))
            .unwrap()
            .try_into()
            .unwrap()
    }

    /// Validator 0 of ethereum-package's default mnemonic. The digests are
    /// `hashlib`'s for the two tagged preimages.
    #[test]
    fn seeds_are_tagged_hashes_of_the_signing_key() {
        let sk = hex32("0dce41fa73ae9f6bdfd51df4d422d75eee174553dba5fd450c4437e4ed3fc903");
        assert_eq!(
            vrf_seed(&sk),
            hex32("543fc5a4d86e79a434e9741770f7ee17c25bdc31be8d61436d7f9836538b03df")
        );
        assert_eq!(
            xmss_seed(&sk),
            hex32("6d78e7072bfcbde1a75261f6e16772ea352de90462819cdc53e05f10d4700ad1")
        );
    }

    /// The leanXMSS key of Lighthouse's
    /// `pq_ethpandaops_keys_and_vrf_tree_boundaries`.
    #[test]
    fn lighthouse_known_xmss_key() {
        let sk = hex32("2892f3ba475c3640a67fe730798ad9c4eed3a6d934db85f91c41cfc837ce8834");
        assert_eq!(
            xmss_key(&sk).public_key().to_bytes(),
            hex32("155a29b971da2b771fdf52c768af63fa03f78f25487e3e0ed03d012b7039d88b")
        );
    }
}
