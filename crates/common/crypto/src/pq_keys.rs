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

/// A validator's leanXMSS key, grown by leanVM's own `lean_xmss` (bindings
/// v0.15.0), the implementation pq-devnet-0 signs with. Generating it builds
/// the key's whole top tree on the calling thread: about 2.4 s, single-threaded,
/// so a caller with many keys spreads them across cores.
pub fn xmss_key(bls_secret_key: &[u8; 32]) -> leanvm_lean_xmss::LeanXmssExpandedSecretKey {
    leanvm_lean_xmss::key_gen(&xmss_seed(bls_secret_key)).0
}

/// The BIP-39 seed of `mnemonic` with no passphrase: PBKDF2-HMAC-SHA512 over
/// 2048 rounds, salted with `"mnemonic"`. What genesis generators and
/// deposit tools derive validator keys from.
///
/// BIP-39 normalizes the mnemonic to NFKD first, which leaves ASCII as it is:
/// a mnemonic with any other character is refused rather than hashed
/// unnormalized into a different seed.
pub fn bip39_seed(mnemonic: &str) -> Option<[u8; 64]> {
    if !mnemonic.is_ascii() {
        return None;
    }
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    let mut seed = [0u8; 64];
    pbkdf2::pbkdf2_hmac::<sha2::Sha512>(words.join(" ").as_bytes(), b"mnemonic", 2048, &mut seed);
    Some(seed)
}

/// The name ethPandaOps' genesis generator (eth-beacon-genesis, `pq` branch
/// from `ff42fce0`) gives the file of a mnemonic's leanXMSS keys and VRF
/// roots, without its `.bin` extension: the first 8 bytes of
/// `sha256("leanxmss-full-keccak-vrf-keys" || seed)`, in hex. Its
/// `--xmss-pubkey-cache` directory and `--xmss-pubkey-url` both name the file
/// this way. The domain is the generator's, and changes with its VRF rule.
pub fn genesis_key_file_name(seed: &[u8; 64]) -> String {
    let digest = sha256_concat(b"leanxmss-full-keccak-vrf-keys", seed);
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The signing key of validator `index` under `seed`: EIP-2333's key at
/// EIP-2334's path `m/12381/3600/<index>/0/0`, as 32 big-endian bytes (what a
/// keystore holds, and what [`xmss_seed`] and [`vrf_seed`] take).
pub fn signing_key(seed: &[u8; 64], index: u32) -> [u8; 32] {
    let master = blst::min_pk::SecretKey::derive_master_eip2333(seed)
        .expect("a 64-byte seed is long enough for EIP-2333");
    [12381, 3600, index, 0, 0]
        .into_iter()
        .fold(master, |key, child| key.derive_child_eip2333(child))
        .to_bytes()
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

    /// ethereum-package's default mnemonic derives the signing key the
    /// seeds test above starts from, and its genesis tooling's published
    /// leanXMSS key for validator 0 (`static_files/xmss-keys`).
    #[test]
    fn the_default_mnemonic_derives_validator_zero() {
        let mnemonic = "giant issue aisle success illegal bike spike question tent bar rely \
                        arctic volcano long crawl hungry vocal artwork sniff fantasy very lucky \
                        have athlete";
        let seed = bip39_seed(mnemonic).unwrap();
        // The package publishes the mnemonic's keys as `b9dec4e1daa17dfe.bin`.
        assert_eq!(genesis_key_file_name(&seed), "b9dec4e1daa17dfe");
        let sk = signing_key(&seed, 0);
        assert_eq!(
            sk,
            hex32("0dce41fa73ae9f6bdfd51df4d422d75eee174553dba5fd450c4437e4ed3fc903")
        );
        assert_eq!(
            xmss_key(&sk).public_key().to_bytes(),
            hex32("d7792e263b94cf0b7a9f70d8374c6d34a600b4247057d4079f810caff711c632")
        );
        assert!(bip39_seed("caf\u{e9}").is_none());
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
