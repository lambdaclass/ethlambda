//! Random write sequences on `List` and `Vector`, checked after every step
//! against `libssz_types::SszList` / `SszVector` holding the same elements:
//! length, every element, iteration, `hash_tree_root` and SSZ bytes must
//! match exactly.
//!
//! Also checks decode parity against the same references on arbitrary and
//! mutated bytes, and that `rebase_on` shares every subtree two states have
//! in common.

use std::collections::BTreeMap;
use std::fmt::Debug;

use ethlambda_ssz_tree::{List, UpdateMap, Value, VecMap, Vector};
use libssz::{SszDecode as _, SszEncode as _};
use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_merkle::{HashTreeRoot, Sha2Hasher};
use libssz_types::{SszList, SszVector};
use proptest::collection::vec;
use proptest::prelude::*;

/// A fixed-size composite element.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
struct Item {
    id: u64,
    data: [u8; 32],
}

/// A variable-size composite element, which exercises the offset table.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
struct Blob {
    id: u64,
    bytes: SszList<u8, 64>,
}

fn item() -> impl Strategy<Value = Item> + Clone {
    (any::<u64>(), any::<[u8; 32]>()).prop_map(|(id, data)| Item { id, data })
}

fn blob() -> impl Strategy<Value = Blob> + Clone {
    (any::<u64>(), vec(any::<u8>(), 0..64)).prop_map(|(id, bytes)| Blob {
        id,
        bytes: bytes.try_into().unwrap(),
    })
}

#[derive(Debug, Clone)]
enum Op<T> {
    Push(T),
    Set(usize, T),
    Apply,
}

fn ops<T: Debug + Clone + 'static>(
    value: impl Strategy<Value = T> + Clone + 'static,
) -> impl Strategy<Value = Vec<Op<T>>> {
    let op = prop_oneof![
        3 => value.clone().prop_map(Op::Push),
        3 => (any::<usize>(), value).prop_map(|(index, value)| Op::Set(index, value)),
        1 => Just(Op::Apply),
    ];
    vec(op, 0..120)
}

fn root<V: HashTreeRoot>(value: &V) -> [u8; 32] {
    HashTreeRoot::hash_tree_root(value, &Sha2Hasher)
}

fn check_list_matches<T, const N: usize, U>(
    list: &List<T, N, U>,
    model: &[T],
) -> Result<(), TestCaseError>
where
    T: Value + Debug,
    U: UpdateMap<T>,
{
    let reference = SszList::<T, N>::try_from(model.to_vec()).unwrap();
    prop_assert_eq!(list.len(), model.len());
    for (index, value) in model.iter().enumerate() {
        prop_assert_eq!(list.get(index), Some(value));
    }
    prop_assert_eq!(list.get(model.len()), None);
    prop_assert_eq!(list.to_vec(), model.to_vec());
    prop_assert_eq!(root(list), root(&reference));
    let bytes = reference.to_ssz();
    prop_assert_eq!(list.to_ssz(), bytes.clone());
    let decoded = List::<T, N, U>::from_ssz_bytes(&bytes).unwrap();
    prop_assert_eq!(root(&decoded), root(&reference));
    Ok(())
}

fn run_list<T, const N: usize, U>(initial: Vec<T>, ops: Vec<Op<T>>) -> Result<(), TestCaseError>
where
    T: Value + Debug,
    U: UpdateMap<T>,
{
    let mut list = List::<T, N, U>::try_from(initial.clone()).unwrap();
    let mut model = initial;
    for op in ops {
        match op {
            Op::Push(value) => {
                let fits = model.len() < N;
                prop_assert_eq!(list.push(value.clone()).is_ok(), fits);
                if fits {
                    model.push(value);
                }
            }
            Op::Set(index, value) => {
                if model.is_empty() {
                    prop_assert!(list.get_mut(0).is_none());
                    continue;
                }
                let index = index % model.len();
                *list.get_mut(index).unwrap() = value.clone();
                model[index] = value;
            }
            Op::Apply => list.apply_updates(),
        }
        check_list_matches(&list, &model)?;
    }
    list.apply_updates();
    check_list_matches(&list, &model)
}

fn run_vector<T, const N: usize, U>(
    initial: Vec<T>,
    writes: Vec<(usize, T, bool)>,
) -> Result<(), TestCaseError>
where
    T: Value + Debug,
    U: UpdateMap<T>,
{
    let mut vector = Vector::<T, N, U>::try_from(initial.clone()).unwrap();
    let mut model = initial;
    for (index, value, apply) in writes {
        let index = index % N;
        vector[index] = value.clone();
        model[index] = value;
        if apply {
            vector.apply_updates();
        }
        let reference = SszVector::<T, N>::try_from(model.clone()).unwrap();
        prop_assert_eq!(vector.to_vec(), model.clone());
        prop_assert_eq!(root(&vector), root(&reference));
        prop_assert_eq!(vector.to_ssz(), reference.to_ssz());
    }
    Ok(())
}

proptest! {
    #[test]
    fn u64_list(initial in vec(any::<u64>(), 0..40), ops in ops(any::<u64>())) {
        run_list::<u64, 64, VecMap<u64>>(initial, ops)?;
    }

    #[test]
    fn u8_list(initial in vec(any::<u8>(), 0..100), ops in ops(any::<u8>())) {
        run_list::<u8, 130, VecMap<u8>>(initial, ops)?;
    }

    #[test]
    fn root_list(initial in vec(any::<[u8; 32]>(), 0..15), ops in ops(any::<[u8; 32]>())) {
        run_list::<[u8; 32], 20, BTreeMap<usize, [u8; 32]>>(initial, ops)?;
    }

    #[test]
    fn item_list(initial in vec(item(), 0..20), ops in ops(item())) {
        run_list::<Item, 33, BTreeMap<usize, Item>>(initial, ops)?;
    }

    #[test]
    fn blob_list(initial in vec(blob(), 0..6), ops in ops(blob())) {
        run_list::<Blob, 9, VecMap<Blob>>(initial, ops)?;
    }

    #[test]
    fn u64_list_at_the_registry_limit(initial in vec(any::<u64>(), 0..20), ops in ops(any::<u64>())) {
        run_list::<u64, { 1 << 40 }, VecMap<u64>>(initial, ops)?;
    }

    /// A leaf holds 512 u64s: this spans several, with the last partial.
    #[test]
    fn u64_list_spanning_leaves(
        initial in vec(any::<u64>(), 0..1600),
        ops in ops(any::<u64>()),
    ) {
        run_list::<u64, 4096, VecMap<u64>>(initial, ops)?;
    }

    /// A leaf holds 64 items: 40 bytes each, a page fits 102, rounded down to a
    /// power of two.
    #[test]
    fn item_list_spanning_leaves(initial in vec(item(), 0..400), ops in ops(item())) {
        run_list::<Item, 1024, BTreeMap<usize, Item>>(initial, ops)?;
    }

    #[test]
    fn u64_vector(
        initial in vec(any::<u64>(), 37),
        writes in vec((any::<usize>(), any::<u64>(), any::<bool>()), 0..60),
    ) {
        run_vector::<u64, 37, VecMap<u64>>(initial, writes)?;
    }

    #[test]
    fn item_vector(
        initial in vec(item(), 5),
        writes in vec((any::<usize>(), item(), any::<bool>()), 0..30),
    ) {
        run_vector::<Item, 5, BTreeMap<usize, Item>>(initial, writes)?;
    }
}

// ── Decode parity on arbitrary bytes ──
//
// The crate decodes fixed-size elements with its own checks rather than
// libssz's `decode_list_with_max`, so these properties pin it to libssz:
// for any input, `List`/`Vector` and `SszList`/`SszVector` must both accept
// with the same elements, or both reject with the same `DecodeError`.

/// One tweak to an otherwise valid encoding.
#[derive(Debug, Clone)]
enum Mutation {
    /// Leaves the bytes untouched.
    None,
    /// XORs the byte at `index % len` with a nonzero value.
    Flip(usize, u8),
    /// Truncates to `len % (original_len + 1)` bytes.
    Truncate(usize),
    /// Appends extra bytes past the end.
    Append(Vec<u8>),
}

fn mutation() -> impl Strategy<Value = Mutation> + Clone {
    prop_oneof![
        1 => Just(Mutation::None),
        3 => (any::<usize>(), 1u8..=u8::MAX).prop_map(|(index, xor)| Mutation::Flip(index, xor)),
        3 => any::<usize>().prop_map(Mutation::Truncate),
        3 => vec(any::<u8>(), 1..8).prop_map(Mutation::Append),
    ]
}

fn apply_mutation(mut bytes: Vec<u8>, mutation: Mutation) -> Vec<u8> {
    match mutation {
        Mutation::None => bytes,
        Mutation::Flip(index, xor) => {
            if !bytes.is_empty() {
                let index = index % bytes.len();
                bytes[index] ^= xor;
            }
            bytes
        }
        Mutation::Truncate(len) => {
            let len = len % (bytes.len() + 1);
            bytes.truncate(len);
            bytes
        }
        Mutation::Append(extra) => {
            bytes.extend(extra);
            bytes
        }
    }
}

/// Arbitrary bytes, mostly derived from a valid encoding of `values` (so
/// offset and length checks are actually reached) but sometimes wholly
/// random.
fn maybe_valid_bytes<T: Value>(
    values: impl Strategy<Value = Vec<T>> + Clone,
) -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        3 => vec(any::<u8>(), 0..=600),
        7 => (values, mutation()).prop_map(|(values, mutation)| {
            apply_mutation(values.to_ssz(), mutation)
        }),
    ]
}

/// `List::<T, N>::from_ssz_bytes` and `SszList::<T, N>::from_ssz_bytes` must
/// agree on `bytes`: both `Ok` with the same elements, or both `Err` with the
/// same `DecodeError`.
fn list_decode_parity<T, const N: usize>(bytes: &[u8]) -> Result<(), TestCaseError>
where
    T: Value + Debug,
{
    let tree_result = List::<T, N>::from_ssz_bytes(bytes);
    let ssz_result = SszList::<T, N>::from_ssz_bytes(bytes);
    match (tree_result, ssz_result) {
        (Ok(tree), Ok(reference)) => prop_assert_eq!(tree.to_vec(), reference.to_vec()),
        (Err(tree_err), Err(ssz_err)) => prop_assert_eq!(tree_err, ssz_err),
        (tree_result, ssz_result) => prop_assert!(
            false,
            "list decode parity mismatch for {bytes:?}: tree={tree_result:?} ssz_list={ssz_result:?}"
        ),
    }
    Ok(())
}

/// `Vector::<T, N>::from_ssz_bytes` and `SszVector::<T, N>::from_ssz_bytes`
/// must agree on `bytes`, the same as [`list_decode_parity`].
fn vector_decode_parity<T, const N: usize>(bytes: &[u8]) -> Result<(), TestCaseError>
where
    T: Value + Debug,
{
    let tree_result = Vector::<T, N>::from_ssz_bytes(bytes);
    let ssz_result = SszVector::<T, N>::from_ssz_bytes(bytes);
    match (tree_result, ssz_result) {
        (Ok(tree), Ok(reference)) => prop_assert_eq!(tree.to_vec(), reference.to_vec()),
        (Err(tree_err), Err(ssz_err)) => prop_assert_eq!(tree_err, ssz_err),
        (tree_result, ssz_result) => prop_assert!(
            false,
            "vector decode parity mismatch for {bytes:?}: tree={tree_result:?} ssz_vector={ssz_result:?}"
        ),
    }
    Ok(())
}

proptest! {
    #[test]
    fn u64_list_decode_parity(bytes in maybe_valid_bytes(vec(any::<u64>(), 0..=15))) {
        list_decode_parity::<u64, 10>(&bytes)?;
    }

    #[test]
    fn item_list_decode_parity(bytes in maybe_valid_bytes(vec(item(), 0..=13))) {
        list_decode_parity::<Item, 8>(&bytes)?;
    }

    #[test]
    fn blob_list_decode_parity(bytes in maybe_valid_bytes(vec(blob(), 0..=9))) {
        list_decode_parity::<Blob, 6>(&bytes)?;
    }

    #[test]
    fn u64_vector_decode_parity(bytes in maybe_valid_bytes(vec(any::<u64>(), 0..=11))) {
        vector_decode_parity::<u64, 6>(&bytes)?;
    }

    #[test]
    fn item_vector_decode_parity(bytes in maybe_valid_bytes(vec(item(), 0..=10))) {
        vector_decode_parity::<Item, 5>(&bytes)?;
    }
}

// ── Rebase: contents and roots survive, equal lists end up shared ──

/// Applies `ops` to `list`, keeping `model` in sync. Unlike `run_list`, makes
/// no assertions: only the final state matters to the rebase property.
fn apply_ops<T, const N: usize, U>(list: &mut List<T, N, U>, model: &mut Vec<T>, ops: Vec<Op<T>>)
where
    T: Value,
    U: UpdateMap<T>,
{
    for op in ops {
        match op {
            Op::Push(value) => {
                if list.push(value.clone()).is_ok() {
                    model.push(value);
                }
            }
            Op::Set(index, value) => {
                if !model.is_empty() {
                    let index = index % model.len();
                    *list.get_mut(index).unwrap() = value.clone();
                    model[index] = value;
                }
            }
            Op::Apply => list.apply_updates(),
        }
    }
}

/// After `orig.rebase_on(base)`: `orig`'s elements are unchanged and its root
/// matches a fresh `SszList` model of them; `base` is untouched (elements and
/// root); and if the two hold equal elements, `orig` shares `base`'s tree.
fn check_rebase<T, const N: usize, U>(
    orig: &mut List<T, N, U>,
    orig_model: &[T],
    base: &List<T, N, U>,
    base_model: &[T],
) -> Result<(), TestCaseError>
where
    T: Value + Debug,
    U: UpdateMap<T>,
{
    orig.rebase_on(base);

    prop_assert_eq!(orig.to_vec(), orig_model.to_vec());
    let orig_reference = SszList::<T, N>::try_from(orig_model.to_vec()).unwrap();
    prop_assert_eq!(root(orig), root(&orig_reference));

    prop_assert_eq!(base.to_vec(), base_model.to_vec());
    let base_reference = SszList::<T, N>::try_from(base_model.to_vec()).unwrap();
    prop_assert_eq!(root(base), root(&base_reference));

    if orig_model == base_model {
        prop_assert!(orig.ptr_eq(base));
    }
    Ok(())
}

/// `orig` derived from `base` by a random edit sequence, `base` at least as
/// long as `orig`'s prefix (`shared_prefix` ends up `base`'s length or less).
fn rebase_grown<T, const N: usize, U>(
    base_values: Vec<T>,
    ops: Vec<Op<T>>,
    hash_base_first: bool,
    hash_orig_first: bool,
) -> Result<(), TestCaseError>
where
    T: Value + Debug,
    U: UpdateMap<T>,
{
    let base = List::<T, N, U>::try_from(base_values.clone()).unwrap();
    if hash_base_first {
        root(&base);
    }

    let mut orig = base.clone();
    let mut orig_model = base_values.clone();
    apply_ops(&mut orig, &mut orig_model, ops);
    orig.apply_updates();

    // Round-trip through SSZ bytes: a freshly decoded tree shares nothing
    // with `base`'s allocation, so any sharing the rebase produces comes from
    // its own content-equality walk.
    let bytes = orig.to_ssz();
    let mut orig = List::<T, N, U>::from_ssz_bytes(&bytes).unwrap();
    if hash_orig_first {
        root(&orig);
    }

    check_rebase(&mut orig, &orig_model, &base, &base_values)
}

/// `base` derived from `orig` by pushing more elements onto a copy, so `orig`
/// is shorter than `base` and `shared_prefix` ends up `orig`'s own length.
fn rebase_shrunk<T, const N: usize, U>(
    orig_values: Vec<T>,
    extra: Vec<T>,
    hash_orig_first: bool,
    hash_base_first: bool,
) -> Result<(), TestCaseError>
where
    T: Value + Debug,
    U: UpdateMap<T>,
{
    let built = List::<T, N, U>::try_from(orig_values.clone()).unwrap();
    let bytes = built.to_ssz();
    let mut orig = List::<T, N, U>::from_ssz_bytes(&bytes).unwrap();
    if hash_orig_first {
        root(&orig);
    }

    let mut base = List::<T, N, U>::try_from(orig_values.clone()).unwrap();
    let mut base_model = orig_values.clone();
    for value in extra {
        if base.push(value.clone()).is_ok() {
            base_model.push(value);
        }
    }
    base.apply_updates();
    if hash_base_first {
        root(&base);
    }

    check_rebase(&mut orig, &orig_values, &base, &base_model)
}

fn zero_prone_u64() -> impl Strategy<Value = u64> + Clone {
    prop_oneof![Just(0u64), any::<u64>()]
}

proptest! {
    #[test]
    fn u64_rebase_grown(
        base_values in vec(zero_prone_u64(), 0..40),
        ops in ops(zero_prone_u64()),
        hash_base_first in any::<bool>(),
        hash_orig_first in any::<bool>(),
    ) {
        rebase_grown::<u64, 64, VecMap<u64>>(base_values, ops, hash_base_first, hash_orig_first)?;
    }

    #[test]
    fn u64_rebase_shrunk(
        orig_values in vec(zero_prone_u64(), 0..30),
        extra in vec(zero_prone_u64(), 0..30),
        hash_orig_first in any::<bool>(),
        hash_base_first in any::<bool>(),
    ) {
        rebase_shrunk::<u64, 64, VecMap<u64>>(orig_values, extra, hash_orig_first, hash_base_first)?;
    }

    #[test]
    fn u64_rebase_grown_spanning_leaves(
        base_values in vec(zero_prone_u64(), 0..1400),
        ops in ops(zero_prone_u64()),
        hash_base_first in any::<bool>(),
        hash_orig_first in any::<bool>(),
    ) {
        rebase_grown::<u64, 4096, VecMap<u64>>(base_values, ops, hash_base_first, hash_orig_first)?;
    }

    #[test]
    fn item_rebase_grown(
        base_values in vec(item(), 0..20),
        ops in ops(item()),
        hash_base_first in any::<bool>(),
        hash_orig_first in any::<bool>(),
    ) {
        rebase_grown::<Item, 33, BTreeMap<usize, Item>>(base_values, ops, hash_base_first, hash_orig_first)?;
    }

    #[test]
    fn item_rebase_shrunk(
        orig_values in vec(item(), 0..15),
        extra in vec(item(), 0..15),
        hash_orig_first in any::<bool>(),
        hash_base_first in any::<bool>(),
    ) {
        rebase_shrunk::<Item, 33, BTreeMap<usize, Item>>(orig_values, extra, hash_orig_first, hash_base_first)?;
    }
}

// ── Shapes the beacon state's tree fields take ──

/// A 32-byte transparent newtype whose `HashTreeRoot` is derived, so it
/// reports a composite (the shape `H256` had before it forwarded the answer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
#[ssz(transparent)]
struct CompositeHash([u8; 32]);

/// The same newtype with `is_basic_type` forwarded, as `H256` now does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, SszEncode, SszDecode)]
#[ssz(transparent)]
struct BasicHash([u8; 32]);

impl HashTreeRoot for BasicHash {
    fn hash_tree_root(&self, hasher: &impl libssz_merkle::Sha256Hasher) -> libssz_merkle::Node {
        HashTreeRoot::hash_tree_root(&self.0, hasher)
    }

    fn is_basic_type() -> bool {
        <[u8; 32] as HashTreeRoot>::is_basic_type()
    }
}

fn composite_hash() -> impl Strategy<Value = CompositeHash> + Clone {
    prop_oneof![
        Just(CompositeHash([0; 32])),
        any::<[u8; 32]>().prop_map(CompositeHash)
    ]
}

fn basic_hash() -> impl Strategy<Value = BasicHash> + Clone {
    prop_oneof![
        Just(BasicHash([0; 32])),
        any::<[u8; 32]>().prop_map(BasicHash)
    ]
}

fn zero_prone_u8() -> impl Strategy<Value = u8> + Clone {
    prop_oneof![3 => Just(0u8), 1 => any::<u8>()]
}

/// Like `check_rebase`, for vectors, which never change length.
fn rebase_vector<T, const N: usize, U>(
    base_values: Vec<T>,
    writes: Vec<(usize, T)>,
    hash_base_first: bool,
) -> Result<(), TestCaseError>
where
    T: Value + Debug,
    U: UpdateMap<T>,
{
    let base = Vector::<T, N, U>::try_from(base_values.clone()).unwrap();
    if hash_base_first {
        root(&base);
    }
    let mut model = base_values.clone();
    let mut orig = base.clone();
    for (index, value) in writes {
        let index = index % N;
        orig[index] = value.clone();
        model[index] = value;
    }
    orig.apply_updates();
    // A decoded copy shares nothing with `base`, so sharing comes from the rebase.
    let bytes = orig.to_ssz();
    let mut orig = Vector::<T, N, U>::from_ssz_bytes(&bytes).unwrap();

    orig.rebase_on(&base);

    let reference = SszVector::<T, N>::try_from(model.clone()).unwrap();
    prop_assert_eq!(orig.to_vec(), model.clone());
    prop_assert_eq!(root(&orig), root(&reference));
    let base_reference = SszVector::<T, N>::try_from(base_values.clone()).unwrap();
    prop_assert_eq!(base.to_vec(), base_values.clone());
    prop_assert_eq!(root(&base), root(&base_reference));
    if model == base_values {
        prop_assert!(orig.ptr_eq(&base));
    }
    Ok(())
}

proptest! {
    /// A leaf holds 4096 u8s: this spans several, with the last partial.
    #[test]
    fn u8_list_spanning_leaves(
        initial in vec(any::<u8>(), 0..10_000),
        ops in ops(any::<u8>()),
    ) {
        run_list::<u8, 16_384, VecMap<u8>>(initial, ops)?;
    }

    /// A leaf holds 512 u64s: 8192 slashings span 16.
    #[test]
    fn u64_vector_spanning_leaves(
        initial in vec(any::<u64>(), 8192),
        writes in vec((any::<usize>(), any::<u64>(), any::<bool>()), 0..40),
    ) {
        run_vector::<u64, 8192, BTreeMap<usize, u64>>(initial, writes)?;
    }

    /// A leaf holds 128 roots: 300 span three.
    #[test]
    fn composite_hash_vector_spanning_leaves(
        initial in vec(composite_hash(), 300),
        writes in vec((any::<usize>(), composite_hash(), any::<bool>()), 0..40),
    ) {
        run_vector::<CompositeHash, 300, BTreeMap<usize, CompositeHash>>(initial, writes)?;
    }

    #[test]
    fn basic_hash_vector_spanning_leaves(
        initial in vec(basic_hash(), 300),
        writes in vec((any::<usize>(), basic_hash(), any::<bool>()), 0..40),
    ) {
        run_vector::<BasicHash, 300, BTreeMap<usize, BasicHash>>(initial, writes)?;
    }

    #[test]
    fn basic_hash_list_spanning_leaves(
        initial in vec(basic_hash(), 0..300),
        ops in ops(basic_hash()),
    ) {
        run_list::<BasicHash, 512, BTreeMap<usize, BasicHash>>(initial, ops)?;
    }

    #[test]
    fn basic_and_composite_hash_collections_have_one_root(
        values in vec(any::<[u8; 32]>(), 0..300),
    ) {
        let basic = List::<BasicHash, 512>::try_from(
            values.iter().copied().map(BasicHash).collect::<Vec<_>>(),
        ).unwrap();
        let composite = List::<CompositeHash, 512>::try_from(
            values.iter().copied().map(CompositeHash).collect::<Vec<_>>(),
        ).unwrap();
        prop_assert_eq!(root(&basic), root(&composite));
        prop_assert_eq!(basic.to_ssz(), composite.to_ssz());
    }

    #[test]
    fn u8_list_decode_parity(bytes in maybe_valid_bytes(vec(any::<u8>(), 0..=300))) {
        list_decode_parity::<u8, 200>(&bytes)?;
    }

    #[test]
    fn basic_hash_vector_decode_parity(bytes in maybe_valid_bytes(vec(basic_hash(), 0..=9))) {
        vector_decode_parity::<BasicHash, 6>(&bytes)?;
    }

    #[test]
    fn u64_vector_decode_parity_multi_leaf(bytes in maybe_valid_bytes(vec(any::<u64>(), 0..=1100))) {
        vector_decode_parity::<u64, 1024>(&bytes)?;
    }

    // Mostly-zero lists: the trailing-zero trap in `rebase_on`.
    #[test]
    fn u8_rebase_grown(
        base_values in vec(zero_prone_u8(), 0..9000),
        ops in ops(zero_prone_u8()),
        hash_base_first in any::<bool>(),
        hash_orig_first in any::<bool>(),
    ) {
        rebase_grown::<u8, 16_384, VecMap<u8>>(base_values, ops, hash_base_first, hash_orig_first)?;
    }

    #[test]
    fn u8_rebase_shrunk(
        orig_values in vec(zero_prone_u8(), 0..9000),
        extra in vec(zero_prone_u8(), 0..300),
        hash_orig_first in any::<bool>(),
        hash_base_first in any::<bool>(),
    ) {
        rebase_shrunk::<u8, 16_384, VecMap<u8>>(orig_values, extra, hash_orig_first, hash_base_first)?;
    }

    #[test]
    fn u64_btree_rebase_grown_spanning_leaves(
        base_values in vec(zero_prone_u64(), 0..1400),
        ops in ops(zero_prone_u64()),
        hash_base_first in any::<bool>(),
        hash_orig_first in any::<bool>(),
    ) {
        rebase_grown::<u64, 4096, BTreeMap<usize, u64>>(base_values, ops, hash_base_first, hash_orig_first)?;
    }

    #[test]
    fn u64_vector_rebase(
        base_values in vec(zero_prone_u64(), 1024),
        writes in vec((any::<usize>(), zero_prone_u64()), 0..8),
        hash_base_first in any::<bool>(),
    ) {
        rebase_vector::<u64, 1024, BTreeMap<usize, u64>>(base_values, writes, hash_base_first)?;
    }

    #[test]
    fn basic_hash_vector_rebase(
        base_values in vec(basic_hash(), 300),
        writes in vec((any::<usize>(), basic_hash()), 0..8),
        hash_base_first in any::<bool>(),
    ) {
        rebase_vector::<BasicHash, 300, BTreeMap<usize, BasicHash>>(base_values, writes, hash_base_first)?;
    }
}

#[test]
fn buffered_forwards_to_lists_and_vectors() {
    use ethlambda_ssz_tree::Buffered;

    let mut list = List::<u64, 64>::try_from(vec![1, 2, 3]).unwrap();
    let mut vector = Vector::<[u8; 32], 4>::try_from(vec![[0u8; 32]; 4]).unwrap();
    list[0] = 9;
    vector[1] = [7; 32];
    let mut fields: Vec<&mut dyn Buffered> = vec![&mut list, &mut vector];
    assert!(fields.iter().all(|f| f.has_pending_updates()));
    fields.iter_mut().for_each(|f| f.apply_updates());
    assert!(fields.iter().all(|f| !f.has_pending_updates()));
}
