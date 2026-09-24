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

use ethlambda_ssz_tree::{List, ProgressiveList, UpdateMap, Value, VecMap, Vector};
use libssz::{DecodeError, SszDecode as _, SszEncode as _};
use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_merkle::{HashTreeRoot, Sha2Hasher};
use libssz_types::{ProgressiveList as RefProgressiveList, SszList, SszVector};
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

// ── ProgressiveList: parity with libssz_types::ProgressiveList (EIP-7916) ──

/// Everything observable about `list` agrees with libssz's
/// `ProgressiveList` over `model`.
fn check_progressive_matches<T, U>(list: &ProgressiveList<T, U>, model: &[T])
where
    T: Value + Debug,
    U: UpdateMap<T>,
{
    let reference = RefProgressiveList::from(model.to_vec());
    assert_eq!(list.len(), model.len());
    for (index, value) in model.iter().enumerate() {
        assert_eq!(list.get(index), Some(value), "index {index}");
    }
    assert_eq!(list.get(model.len()), None);
    assert_eq!(list.to_vec(), model);
    assert_eq!(list.iter().len(), model.len());
    assert_eq!(root(list), root(&reference));
    let bytes = list.to_ssz();
    assert_eq!(bytes, reference.to_ssz());
    let decoded = ProgressiveList::<T, U>::from_ssz_bytes(&bytes).expect("round trip");
    assert_eq!(root(&decoded), root(&reference));
}

fn run_progressive<T, U>(initial: Vec<T>, ops: Vec<Op<T>>)
where
    T: Value + Debug,
    U: UpdateMap<T>,
{
    let mut list = ProgressiveList::<T, U>::from(initial.clone());
    let mut model = initial;
    check_progressive_matches(&list, &model);
    for op in ops {
        match op {
            Op::Push(value) => {
                list.push(value.clone())
                    .expect("a progressive list has no limit");
                model.push(value);
            }
            Op::Set(index, value) if !model.is_empty() => {
                let index = index % model.len();
                list[index] = value.clone();
                model[index] = value;
            }
            Op::Set(..) => {}
            Op::Apply => list.apply_updates(),
        }
        check_progressive_matches(&list, &model);
    }
}

proptest! {
    // Packed: 4 per chunk, so subtrees start at elements 0, 4, 20, 84, 340.
    #[test]
    fn progressive_u64(initial in vec(any::<u64>(), 0..400), ops in ops(any::<u64>())) {
        run_progressive::<u64, VecMap<u64>>(initial, ops);
    }
    // Composite: one per chunk, subtrees start at 0, 1, 5, 21, 85.
    #[test]
    fn progressive_item(initial in vec(item(), 0..100), ops in ops(item())) {
        run_progressive::<Item, BTreeMap<usize, Item>>(initial, ops);
    }
    // Variable-size elements: the offset table spans every subtree.
    #[test]
    fn progressive_blob(initial in vec(blob(), 0..30), ops in ops(blob())) {
        run_progressive::<Blob, VecMap<Blob>>(initial, ops);
    }
}

#[test]
fn progressive_boundaries_hash_like_libssz() {
    // 0, 1, 5, 21, 85, 341 are the composite subtree boundaries (packed u64
    // boundaries are 4, 20, 84, 340); 6, 22, 86, 342 are one past each of
    // those, so a subtree that has just opened with a single element is
    // exercised too, not only subtrees that are exactly full or exactly one
    // short.
    for len in [0usize, 1, 2, 4, 5, 6, 20, 21, 22, 84, 85, 86, 340, 341, 342] {
        let values: Vec<u64> = (0..len as u64).collect();
        check_progressive_matches(&ProgressiveList::<u64>::from(values.clone()), &values);
        let items: Vec<[u8; 32]> = (0..len).map(|i| [i as u8; 32]).collect();
        check_progressive_matches(&ProgressiveList::<[u8; 32]>::from(items.clone()), &items);
    }
}

// ── ProgressiveList: iter_from ──

#[test]
fn progressive_iter_from_starts_at_the_given_index() {
    // u64 packed boundaries: subtrees start at elements 0, 4, 20, 84, 340.
    let values: Vec<u64> = (0..50).collect();
    let list = ProgressiveList::<u64>::from(values.clone());

    // Mid-subtree: inside subtree 2, which spans elements 20..84.
    assert_eq!(
        list.iter_from(30).copied().collect::<Vec<_>>(),
        values[30..]
    );
    // Exactly at a subtree boundary: the first element of the next subtree.
    assert_eq!(list.iter_from(4).copied().collect::<Vec<_>>(), values[4..]);
    assert_eq!(
        list.iter_from(20).copied().collect::<Vec<_>>(),
        values[20..]
    );
    // At and past the end.
    assert_eq!(list.iter_from(50).count(), 0);
    assert_eq!(list.iter_from(100).count(), 0);
    assert_eq!(list.iter().len(), 50);
}

// ── ProgressiveList: decode errors ──

#[test]
fn progressive_decode_rejects_a_length_not_a_multiple_of_the_element_size() {
    let bytes = vec![0u8; 7]; // u64 is 8 bytes wide; 7 does not divide evenly.
    let err = ProgressiveList::<u64>::from_ssz_bytes(&bytes).unwrap_err();
    assert_eq!(
        err,
        DecodeError::InvalidByteLength {
            expected: 8,
            got: 7
        }
    );
}

#[test]
fn progressive_decode_rejects_a_bad_offset_table_for_variable_size_elements() {
    // First offset is 5, not a multiple of 4: the same bad input list.rs's
    // own `decoding_a_first_offset_that_is_not_a_multiple_of_four_is_rejected_like_ssz_list`
    // uses.
    let bytes = vec![5u8, 0, 0, 0, 0];
    let ours = ProgressiveList::<Blob>::from_ssz_bytes(&bytes).unwrap_err();
    let reference = RefProgressiveList::<Blob>::from_ssz_bytes(&bytes).unwrap_err();
    assert_eq!(ours, reference);
}

#[test]
fn progressive_decode_reports_the_first_bad_fixed_size_element_not_the_last() {
    // Two invalid `bool` bytes (neither 0 nor 1). The non-fused `map_while`
    // bug this guards against (see the `.fuse()` comment in
    // progressive_list.rs) would keep decoding past the first bad byte and
    // surface the second failure instead of the first.
    let bytes = vec![1u8, 2, 1, 3, 1];
    let ours = ProgressiveList::<bool>::from_ssz_bytes(&bytes).unwrap_err();
    let reference = RefProgressiveList::<bool>::from_ssz_bytes(&bytes).unwrap_err();
    assert_eq!(ours, reference);
    assert_eq!(ours, DecodeError::InvalidBooleanByte(2));
}

// ── ProgressiveList: rebase ──

/// Applies `ops` to `list`, keeping `model` in sync. Mirrors `apply_ops`,
/// unlike `run_progressive`, makes no assertions: only the final state
/// matters to the rebase property.
fn apply_progressive_ops<T, U>(
    list: &mut ProgressiveList<T, U>,
    model: &mut Vec<T>,
    ops: Vec<Op<T>>,
) where
    T: Value,
    U: UpdateMap<T>,
{
    for op in ops {
        match op {
            Op::Push(value) => {
                list.push(value.clone())
                    .expect("a progressive list has no limit");
                model.push(value);
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
/// matches a fresh `libssz_types::ProgressiveList` model of them; `base` is
/// untouched (elements and root); and if the two hold equal elements (so the
/// same number of subtrees too), `orig` shares every one of `base`'s
/// subtrees. `ProgressiveList::ptr_eq` only compares the whole list (per-
/// subtree sharing is not part of the public API), so unequal subtree counts
/// are not otherwise observable here; the deterministic test below checks
/// that case a different way.
fn check_progressive_rebase<T, U>(
    orig: &mut ProgressiveList<T, U>,
    orig_model: &[T],
    base: &ProgressiveList<T, U>,
    base_model: &[T],
) -> Result<(), TestCaseError>
where
    T: Value + Debug,
    U: UpdateMap<T>,
{
    orig.rebase_on(base);

    prop_assert_eq!(orig.to_vec(), orig_model.to_vec());
    let orig_reference = RefProgressiveList::from(orig_model.to_vec());
    prop_assert_eq!(root(orig), root(&orig_reference));

    prop_assert_eq!(base.to_vec(), base_model.to_vec());
    let base_reference = RefProgressiveList::from(base_model.to_vec());
    prop_assert_eq!(root(base), root(&base_reference));

    if orig_model == base_model {
        prop_assert!(orig.ptr_eq(base));
    }
    Ok(())
}

/// `orig` derived from `base` by a random edit sequence, so `base` ends up
/// with fewer (or equal) subtrees than `orig`: `Op::Push` only grows,
/// `Op::Set` never removes a subtree.
fn progressive_rebase_grown<T, U>(
    base_values: Vec<T>,
    ops: Vec<Op<T>>,
    hash_base_first: bool,
    hash_orig_first: bool,
) -> Result<(), TestCaseError>
where
    T: Value + Debug,
    U: UpdateMap<T>,
{
    let base = ProgressiveList::<T, U>::from(base_values.clone());
    if hash_base_first {
        root(&base);
    }

    let mut orig = base.clone();
    let mut orig_model = base_values.clone();
    apply_progressive_ops(&mut orig, &mut orig_model, ops);
    orig.apply_updates();

    // Round-trip through SSZ bytes: a freshly decoded list shares nothing
    // with `base`'s allocation, so any sharing the rebase produces comes
    // from its own content-equality walk.
    let bytes = orig.to_ssz();
    let mut orig = ProgressiveList::<T, U>::from_ssz_bytes(&bytes).unwrap();
    if hash_orig_first {
        root(&orig);
    }

    check_progressive_rebase(&mut orig, &orig_model, &base, &base_values)
}

/// `base` derived from `orig` by pushing more elements onto a copy, so `base`
/// ends up with more (or equal) subtrees than `orig`.
fn progressive_rebase_shrunk<T, U>(
    orig_values: Vec<T>,
    extra: Vec<T>,
    hash_orig_first: bool,
    hash_base_first: bool,
) -> Result<(), TestCaseError>
where
    T: Value + Debug,
    U: UpdateMap<T>,
{
    let built = ProgressiveList::<T, U>::from(orig_values.clone());
    let bytes = built.to_ssz();
    let mut orig = ProgressiveList::<T, U>::from_ssz_bytes(&bytes).unwrap();
    if hash_orig_first {
        root(&orig);
    }

    let mut base = ProgressiveList::<T, U>::from(orig_values.clone());
    let mut base_model = orig_values.clone();
    for value in extra {
        base.push(value.clone())
            .expect("a progressive list has no limit");
        base_model.push(value);
    }
    base.apply_updates();
    if hash_base_first {
        root(&base);
    }

    check_progressive_rebase(&mut orig, &orig_values, &base, &base_model)
}

proptest! {
    #[test]
    fn progressive_u64_rebase_grown(
        base_values in vec(zero_prone_u64(), 0..400),
        ops in ops(zero_prone_u64()),
        hash_base_first in any::<bool>(),
        hash_orig_first in any::<bool>(),
    ) {
        progressive_rebase_grown::<u64, VecMap<u64>>(base_values, ops, hash_base_first, hash_orig_first)?;
    }

    #[test]
    fn progressive_u64_rebase_shrunk(
        orig_values in vec(zero_prone_u64(), 0..400),
        extra in vec(zero_prone_u64(), 0..400),
        hash_orig_first in any::<bool>(),
        hash_base_first in any::<bool>(),
    ) {
        progressive_rebase_shrunk::<u64, VecMap<u64>>(orig_values, extra, hash_orig_first, hash_base_first)?;
    }

    #[test]
    fn progressive_item_rebase_grown(
        base_values in vec(item(), 0..100),
        ops in ops(item()),
        hash_base_first in any::<bool>(),
        hash_orig_first in any::<bool>(),
    ) {
        progressive_rebase_grown::<Item, BTreeMap<usize, Item>>(base_values, ops, hash_base_first, hash_orig_first)?;
    }

    #[test]
    fn progressive_item_rebase_shrunk(
        orig_values in vec(item(), 0..100),
        extra in vec(item(), 0..100),
        hash_orig_first in any::<bool>(),
        hash_base_first in any::<bool>(),
    ) {
        progressive_rebase_shrunk::<Item, BTreeMap<usize, Item>>(orig_values, extra, hash_orig_first, hash_base_first)?;
    }
}

/// `rebase_on` reads a subtree's *committed* content only. A pending push
/// that has just opened a new subtree (buffered, not yet folded into that
/// subtree's own tree) contributes nothing to share until `apply_updates`
/// runs. `orig` has the same subtree count as `base` (341 elements too), so
/// `rebase_on`'s positional zip actually reaches the pending subtree rather
/// than stopping short at `orig`'s length; its own value there differs from
/// `base`'s pending one, so adopting it (a bug) would be observable. `base`
/// is `&Self`, so rebasing another list onto it cannot change it either. A
/// second rebase, after `base.apply_updates()` makes the two lists equal
/// again, shows sharing resumes once there is something committed to share.
#[test]
fn progressive_rebase_ignores_a_pending_push_into_a_new_subtree() {
    // u64 packs 4 per chunk; 340 elements exactly fill subtrees 0..3
    // (capacities 4, 16, 64, 256), so a 341st element opens subtree 4.
    let full: Vec<u64> = (0..340).collect();
    let mut base = ProgressiveList::<u64>::from(full.clone());
    base.push(9999).expect("a progressive list has no limit"); // buffered

    let mut orig_values = full.clone();
    orig_values.push(1111); // differs from base's pending 9999
    let mut orig = ProgressiveList::<u64>::from(orig_values.clone());
    orig.rebase_on(&base);

    assert_eq!(orig.to_vec(), orig_values);
    assert_eq!(
        root(&orig),
        root(&RefProgressiveList::from(orig_values.clone()))
    );
    let mut base_expected = full.clone();
    base_expected.push(9999);
    assert_eq!(base.to_vec(), base_expected);

    // Once the pending write is folded in, the two lists have the same
    // shape and content again, so a fresh rebase reclaims every subtree,
    // including the one that was pending above.
    base.apply_updates();
    let mut orig = ProgressiveList::<u64>::from(base_expected);
    orig.rebase_on(&base);
    assert!(orig.ptr_eq(&base));
}
