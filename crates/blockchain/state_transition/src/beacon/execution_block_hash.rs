//! The execution block hash of a gloas payload, recomputed from its fields:
//! gloas `p2p-interface.md`'s `keccak256`, `compute_ordered_trie_root` and
//! `compute_execution_block_hash` (consensus-specs #5770, v1.7.0-beta.5).
//!
//! The `execution_payload` gossip rule rejects an envelope whose payload's
//! `block_hash` is not the hash of the header its own fields describe, so a
//! node can refuse a forged payload before the execution client sees it. That
//! needs the execution layer's header encoding, which nothing else in this
//! crate does: RLP, Keccak-256, and the root of a Merkle Patricia Trie keyed by
//! `rlp(index)`. All three are small and fixed, so they are written out here
//! rather than taken from an execution-layer crate this one does not otherwise
//! depend on.

use sha3::{Digest, Keccak256};

use crate::beacon::containers::gloas;
use crate::beacon::hash::hash;
use crate::beacon::primitives::{Bytes32, ExecutionBlockHash, H256, Root, U256};
use crate::beacon::stf::gloas::get_execution_requests_list;

/// The specification's `keccak256`.
pub fn keccak256(data: &[u8]) -> Bytes32 {
    H256(Keccak256::digest(data).into())
}

/// The specification's `compute_ordered_trie_root`: the root of the Merkle
/// Patricia Trie mapping `rlp_encode(index)` to each value, in order.
pub fn compute_ordered_trie_root<V: AsRef<[u8]>>(values: &[V]) -> Bytes32 {
    let entries = values
        .iter()
        .enumerate()
        .map(|(index, value)| (rlp::uint(index as u64), value.as_ref()))
        .collect();
    trie_root(entries)
}

/// The root of the Merkle Patricia Trie holding `entries`, whose keys are
/// distinct.
fn trie_root(entries: Vec<(Vec<u8>, &[u8])>) -> Bytes32 {
    let mut items: Vec<(Vec<u8>, &[u8])> = entries
        .into_iter()
        .map(|(key, value)| (nibbles(&key), value))
        .collect();
    if items.is_empty() {
        // The empty trie: `keccak256(rlp(b""))`.
        return keccak256(&rlp::bytes(&[]));
    }
    items.sort_by(|a, b| a.0.cmp(&b.0));
    keccak256(&trie_node(&items, 0))
}

/// The specification's `compute_execution_block_hash`: the hash of the
/// execution block header `payload` describes, with
/// `parent_beacon_block_root` and the requests hash of `execution_requests`
/// filled in from the envelope.
pub fn compute_execution_block_hash(
    payload: &gloas::ExecutionPayload,
    parent_beacon_block_root: Root,
    execution_requests: &gloas::ExecutionRequests,
) -> ExecutionBlockHash {
    let ommers_hash = keccak256(&rlp::list(&[]));
    let transactions: Vec<&[u8]> = payload
        .transactions
        .iter()
        .map(|transaction| &transaction[..])
        .collect();
    let transactions_root = compute_ordered_trie_root(&transactions);
    let withdrawals: Vec<Vec<u8>> = payload
        .withdrawals
        .iter()
        .map(|withdrawal| {
            rlp::list(&[
                rlp::uint(withdrawal.index),
                rlp::uint(withdrawal.validator_index),
                rlp::bytes(&withdrawal.address.0),
                rlp::uint(withdrawal.amount),
            ])
        })
        .collect();
    let withdrawals_root = compute_ordered_trie_root(&withdrawals);
    let mut request_hashes = Vec::new();
    for request in get_execution_requests_list(execution_requests) {
        request_hashes.extend_from_slice(&hash(&request).0);
    }
    let requests_hash = hash(&request_hashes);
    let block_access_list_hash = keccak256(&payload.block_access_list);

    let header = rlp::list(&[
        rlp::bytes(&payload.parent_hash.0),
        rlp::bytes(&ommers_hash.0),
        rlp::bytes(&payload.fee_recipient.0),
        rlp::bytes(&payload.state_root.0),
        rlp::bytes(&transactions_root.0),
        rlp::bytes(&payload.receipts_root.0),
        rlp::bytes(&payload.logs_bloom),
        // Difficulty.
        rlp::uint(0),
        rlp::uint(payload.block_number),
        rlp::uint(payload.gas_limit),
        rlp::uint(payload.gas_used),
        rlp::uint(payload.timestamp),
        rlp::bytes(&payload.extra_data),
        rlp::bytes(&payload.prev_randao.0),
        // Nonce: eight zero bytes.
        rlp::bytes(&[0u8; 8]),
        rlp::uint256(&payload.base_fee_per_gas),
        rlp::bytes(&withdrawals_root.0),
        rlp::uint(payload.blob_gas_used),
        rlp::uint(payload.excess_blob_gas),
        rlp::bytes(&parent_beacon_block_root.0),
        rlp::bytes(&requests_hash.0),
        rlp::bytes(&block_access_list_hash.0),
        rlp::uint(payload.slot_number),
    ]);
    keccak256(&header)
}

/// `key`'s nibbles, high half of each byte first.
fn nibbles(key: &[u8]) -> Vec<u8> {
    key.iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .collect()
}

/// The hex-prefix encoding of a leaf's or an extension's remaining `path`.
fn hex_prefix(path: &[u8], leaf: bool) -> Vec<u8> {
    let flag = if leaf { 2 } else { 0 } + (path.len() % 2) as u8;
    let mut out = Vec::with_capacity(path.len() / 2 + 1);
    let rest = if path.len() % 2 == 1 {
        out.push((flag << 4) | path[0]);
        &path[1..]
    } else {
        out.push(flag << 4);
        path
    };
    out.extend(rest.chunks(2).map(|pair| (pair[0] << 4) | pair[1]));
    out
}

/// How a node is referenced from its parent: inline when its encoding is
/// shorter than a hash, else by the Keccak-256 of that encoding.
fn node_reference(encoded: Vec<u8>) -> Vec<u8> {
    if encoded.len() < 32 {
        encoded
    } else {
        rlp::bytes(&keccak256(&encoded).0)
    }
}

/// The RLP encoding of the trie node holding `items` (sorted by key, keys
/// distinct), each key consumed up to `depth` nibbles already.
fn trie_node(items: &[(Vec<u8>, &[u8])], depth: usize) -> Vec<u8> {
    if let [(key, value)] = items {
        return rlp::list(&[
            rlp::bytes(&hex_prefix(&key[depth..], true)),
            rlp::bytes(value),
        ]);
    }
    // Sorted, so the first and last keys bound every shared prefix.
    let (first, last) = (&items[0].0, &items[items.len() - 1].0);
    let shared = first[depth..]
        .iter()
        .zip(&last[depth..])
        .take_while(|(a, b)| a == b)
        .count();
    if shared > 0 {
        let child = trie_node(items, depth + shared);
        return rlp::list(&[
            rlp::bytes(&hex_prefix(&first[depth..depth + shared], false)),
            node_reference(child),
        ]);
    }
    let mut slots: Vec<Vec<u8>> = Vec::with_capacity(17);
    let mut value: &[u8] = &[];
    let mut rest = items;
    // A key that ends here is the branch's own value; sorting puts it first.
    if let Some(((key, own), tail)) = rest.split_first()
        && key.len() == depth
    {
        value = own;
        rest = tail;
    }
    for nibble in 0..16u8 {
        let count = rest
            .iter()
            .take_while(|(key, _)| key[depth] == nibble)
            .count();
        let (group, tail) = rest.split_at(count);
        rest = tail;
        slots.push(if group.is_empty() {
            rlp::bytes(&[])
        } else {
            node_reference(trie_node(group, depth + 1))
        });
    }
    slots.push(rlp::bytes(value));
    rlp::list(&slots)
}

/// Recursive Length Prefix encoding, as much of it as an execution header and
/// its tries need. Every function returns a complete encoded item.
mod rlp {
    use super::U256;

    fn header(short_base: u8, long_base: u8, len: usize) -> Vec<u8> {
        if len <= 55 {
            return vec![short_base + len as u8];
        }
        let len_bytes = minimal_be(len as u64);
        let mut out = Vec::with_capacity(1 + len_bytes.len());
        out.push(long_base + len_bytes.len() as u8);
        out.extend_from_slice(&len_bytes);
        out
    }

    /// `value`'s big-endian bytes without leading zeros; empty for zero.
    fn minimal_be(value: u64) -> Vec<u8> {
        let bytes = value.to_be_bytes();
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
        bytes[start..].to_vec()
    }

    /// A byte string.
    pub(super) fn bytes(data: &[u8]) -> Vec<u8> {
        if let [byte] = data
            && *byte < 0x80
        {
            return vec![*byte];
        }
        let mut out = header(0x80, 0xb7, data.len());
        out.extend_from_slice(data);
        out
    }

    /// A list of already-encoded items.
    pub(super) fn list(items: &[Vec<u8>]) -> Vec<u8> {
        let len = items.iter().map(Vec::len).sum();
        let mut out = header(0xc0, 0xf7, len);
        for item in items {
            out.extend_from_slice(item);
        }
        out
    }

    /// An integer: its minimal big-endian bytes as a string.
    pub(super) fn uint(value: u64) -> Vec<u8> {
        bytes(&minimal_be(value))
    }

    /// A 256-bit integer, stored little-endian (see [`U256`]).
    pub(super) fn uint256(value: &U256) -> Vec<u8> {
        let mut be = value.0;
        be.reverse();
        let start = be.iter().position(|&b| b != 0).unwrap_or(be.len());
        bytes(&be[start..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(hash: Bytes32) -> String {
        hex::encode(hash.0)
    }

    #[test]
    fn keccak_of_the_empty_string() {
        assert_eq!(
            hex32(keccak256(&[])),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    /// The empty trie's root and the empty ommers list's hash, the two
    /// constants every post-merge header carries.
    #[test]
    fn the_empty_trie_and_the_empty_ommers_list() {
        assert_eq!(
            hex32(compute_ordered_trie_root::<&[u8]>(&[])),
            "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
        );
        assert_eq!(
            hex32(keccak256(&rlp::list(&[]))),
            "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"
        );
    }

    #[test]
    fn rlp_follows_the_short_and_long_forms() {
        assert_eq!(rlp::bytes(&[]), vec![0x80]);
        assert_eq!(rlp::bytes(&[0x7f]), vec![0x7f]);
        assert_eq!(rlp::bytes(&[0x80]), vec![0x81, 0x80]);
        assert_eq!(rlp::uint(0), vec![0x80]);
        assert_eq!(rlp::uint(1024), vec![0x82, 0x04, 0x00]);
        let long = [0xaa; 56];
        let encoded = rlp::bytes(&long);
        assert_eq!(&encoded[..2], &[0xb8, 56]);
        assert_eq!(encoded.len(), 58);
        assert_eq!(rlp::list(&[]), vec![0xc0]);
        let mut u = U256::ZERO;
        u.0[0] = 7;
        assert_eq!(rlp::uint256(&u), vec![0x07]);
        assert_eq!(rlp::uint256(&U256::ZERO), vec![0x80]);
    }

    #[test]
    fn hex_prefix_marks_parity_and_leafness() {
        assert_eq!(hex_prefix(&[1, 2, 3], false), vec![0x11, 0x23]);
        assert_eq!(hex_prefix(&[0, 1, 2, 3], false), vec![0x00, 0x01, 0x23]);
        assert_eq!(hex_prefix(&[1, 2, 3], true), vec![0x31, 0x23]);
        assert_eq!(hex_prefix(&[0, 15, 1, 12], true), vec![0x20, 0x0f, 0x1c]);
    }

    /// `ethereum/tests`' `TrieTests/trieanyorder.json`, every case: leaves,
    /// extensions, branches, inline nodes, and keys that are prefixes of
    /// other keys (`do`/`dog`/`doge`, `te`/`test`), whose values sit in a
    /// branch.
    #[test]
    fn trie_roots_match_ethereum_tests_trieanyorder() {
        /// One case: its `(key, value)` entries and the expected root.
        type TrieCase<'a> = (&'a [(&'a [u8], &'a [u8])], &'a str);
        let cases: &[TrieCase] = &[
            (
                &[(b"A", b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")],
                "d23786fb4a010da3ce639d66d5e904a11dbc02746d1ce25029e53290cabf28ab",
            ),
            (
                &[
                    (b"doe", b"reindeer"),
                    (b"dog", b"puppy"),
                    (b"dogglesworth", b"cat"),
                ],
                "8aad789dff2f538bca5d8ea56e8abe10f4c7ba3a5dea95fea4cd6e7c3a1168d3",
            ),
            (
                &[
                    (b"do", b"verb"),
                    (b"horse", b"stallion"),
                    (b"doge", b"coin"),
                    (b"dog", b"puppy"),
                ],
                "5991bb8c6514148a29db676a14ac506cd2cd5775ace63c30a4fe457715e9ac84",
            ),
            (
                &[(b"foo", b"bar"), (b"food", b"bass")],
                "17beaa1648bafa633cda809c90c04af50fc8aed3cb40d16efbddee6fdf63c4c3",
            ),
            (
                &[(b"be", b"e"), (b"dog", b"puppy"), (b"bed", b"d")],
                "3f67c7a47520f79faa29255d2d3c084a7a6df0453116ed7232ff10277a8be68b",
            ),
            (
                &[(b"test", b"test"), (b"te", b"testy")],
                "8452568af70d8d140f58d941338542f645fcca50094b20f3c3d8c3df49337928",
            ),
            (
                &[
                    (&[0x00, 0x45], &[0x01, 0x23, 0x45, 0x67, 0x89]),
                    (&[0x45, 0x00], &[0x98, 0x76, 0x54, 0x32, 0x10]),
                ],
                "285505fcabe84badc8aa310e2aae17eddc7d120aabec8a476902c8184b3a3503",
            ),
        ];
        for (entries, root) in cases {
            let entries = entries
                .iter()
                .map(|(key, value)| (key.to_vec(), *value))
                .collect();
            assert_eq!(hex32(trie_root(entries)), *root);
        }
    }

    /// An ordered trie is the generic one keyed by `rlp(index)`: index 0 is
    /// `0x80`, and 128 is the first two-byte key (`0x8180`).
    #[test]
    fn an_ordered_trie_is_keyed_by_the_rlp_of_each_index() {
        let values: Vec<Vec<u8>> = (0..200u32).map(|i| i.to_be_bytes().to_vec()).collect();
        let entries = values
            .iter()
            .enumerate()
            .map(|(index, value)| (rlp::uint(index as u64), value.as_slice()))
            .collect();
        assert_eq!(compute_ordered_trie_root(&values), trie_root(entries));
        assert_eq!(rlp::uint(0), vec![0x80]);
        assert_eq!(rlp::uint(128), vec![0x81, 0x80]);
    }
}
