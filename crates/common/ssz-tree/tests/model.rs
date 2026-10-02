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

/// How `run_progressive` writes an element in place.
#[derive(Clone, Copy)]
enum Write {
    /// `list[index] = value`.
    IndexMut,
    /// `*list.get_mut(index) = value`, the path the beacon state's balances take.
    GetMut,
}

fn run_progressive<T, U>(initial: Vec<T>, ops: Vec<Op<T>>, write: Write)
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
                match write {
                    Write::IndexMut => list[index] = value.clone(),
                    Write::GetMut => *list.get_mut(index).expect("in bounds") = value.clone(),
                }
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
        run_progressive::<u64, VecMap<u64>>(initial, ops, Write::IndexMut);
    }
    // Composite: one per chunk, subtrees start at 0, 1, 5, 21, 85.
    #[test]
    fn progressive_item(initial in vec(item(), 0..100), ops in ops(item())) {
        run_progressive::<Item, BTreeMap<usize, Item>>(initial, ops, Write::IndexMut);
    }
    // Variable-size elements: the offset table spans every subtree.
    #[test]
    fn progressive_blob(initial in vec(blob(), 0..30), ops in ops(blob())) {
        run_progressive::<Blob, VecMap<Blob>>(initial, ops, Write::IndexMut);
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

// ── ProgressiveList: subtrees that span leaves ──
//
// The tests above stop at 342 elements, where every packed `u64` subtree still
// fits in one leaf of the paged tree (a leaf holds 512 `u64`s). Subtree `k` of
// a progressive list holds `4^k` chunks of four `u64`s, so packed `u64`
// subtrees start at element 0, 4, 20, 84, 340, 1364 and 5460, and each is
// paged from its own start. The subtree that starts at 340 holds 1024
// elements, so its second leaf starts at element 852 (340 + 512). The one
// that starts at 1364 holds 4096, so its leaves start at 1364, 1876, 2388, and
// so on in steps of 512. The cases below run from element 1364 to 5461, which
// covers the whole of the subtree that starts at 1364 and the start of the
// next.

proptest! {
    // Each case hashes thousands of elements after every operation, so far
    // fewer cases than the default keep the run short.
    #![proptest_config(ProptestConfig::with_cases(16))]

    /// The whole subtree that starts at element 1364 (which spans eight
    /// leaves), and the start of the one at 5460.
    #[test]
    fn progressive_u64_spanning_leaves(
        initial in vec(any::<u64>(), 1364..=5461),
        ops in ops(any::<u64>()),
    ) {
        run_progressive::<u64, VecMap<u64>>(initial, ops, Write::GetMut);
    }

    /// Starts just short of element 1364, so pushes open that subtree.
    #[test]
    fn progressive_u64_pushes_open_a_spanning_subtree(
        initial in vec(any::<u64>(), 1350..=1364),
        ops in ops(any::<u64>()),
    ) {
        run_progressive::<u64, VecMap<u64>>(initial, ops, Write::GetMut);
    }

    /// Starts just short of element 5460, so pushes open that subtree.
    #[test]
    fn progressive_u64_pushes_open_the_next_spanning_subtree(
        initial in vec(any::<u64>(), 5440..=5460),
        ops in ops(any::<u64>()),
    ) {
        run_progressive::<u64, VecMap<u64>>(initial, ops, Write::GetMut);
    }
}

#[test]
fn progressive_spanning_boundaries_hash_like_libssz() {
    // Around the second leaf of the subtree that starts at 340 (852), around the
    // start of the subtree that starts at 1364 and its second and third leaves
    // (1876, 2388), and around the start of the next subtree (5460).
    for len in [
        851usize, 852, 853, 1363, 1364, 1365, 1875, 1876, 1877, 2387, 2388, 2389, 5459, 5460, 5461,
    ] {
        let values: Vec<u64> = (0..len as u64).collect();
        check_progressive_matches(&ProgressiveList::<u64>::from(values.clone()), &values);
    }
}

#[test]
fn progressive_writes_and_pushes_across_the_first_spanning_boundary() {
    let mut model: Vec<u64> = (0..1363).collect();
    let mut list = ProgressiveList::<u64>::from(model.clone());
    check_progressive_matches(&list, &model);

    // Writes on both sides of the boundary and at leaf edges, pending until
    // the push below opens the subtree that starts at element 1364.
    for index in [0usize, 339, 340, 851, 852, 1362] {
        *list.get_mut(index).expect("in bounds") = 0xdead_0000 + index as u64;
        model[index] = 0xdead_0000 + index as u64;
    }
    check_progressive_matches(&list, &model);

    for value in 0..12u64 {
        list.push(value).expect("a progressive list has no limit");
        model.push(value);
        check_progressive_matches(&list, &model);
    }

    // Grow past the second leaf of the new subtree (1876), then write on both
    // sides of each edge.
    for value in 12..520u64 {
        list.push(value).expect("a progressive list has no limit");
        model.push(value);
    }
    check_progressive_matches(&list, &model);
    for index in [1363usize, 1364, 1365, 1374, 1875, 1876] {
        *list.get_mut(index).expect("in bounds") = !(index as u64);
        model[index] = !(index as u64);
        list.apply_updates();
        check_progressive_matches(&list, &model);
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

// ── Write cursor: random sweeps match a model, and clones are untouched ──

/// What a sweep does to one element, picked by `action % 5`.
type Decision<T> = (u8, T);

fn decisions<T: Debug + Clone + 'static>(
    value: impl Strategy<Value = T> + Clone + 'static,
) -> impl Strategy<Value = Vec<Decision<T>>> {
    vec((any::<u8>(), value), 1..9)
}

/// Runs one sweep over `list`, mirroring every write in `model`, and stops
/// after `stop_at % (len + 1)` elements. Decision per element: skip; `set` a
/// new value; `set` the same value; `make_mut` and write a new value;
/// `make_mut` and write the same value.
fn sweep<T, const N: usize, U>(
    list: &mut List<T, N, U>,
    model: &mut [T],
    stop_at: usize,
    decisions: &[Decision<T>],
    noop_only: bool,
) -> Result<(), TestCaseError>
where
    T: Value + Debug,
    U: UpdateMap<T>,
{
    let stop = stop_at % (model.len() + 1);
    let mut pass = list.iter_cow();
    let mut seen = 0;
    while let Some(mut element) = pass.next_cow() {
        if seen == stop {
            break;
        }
        let index = element.index();
        prop_assert_eq!(index, seen);
        prop_assert_eq!(&*element, &model[index]);
        let (action, value) = &decisions[index % decisions.len()];
        let action = if noop_only {
            [0, 2, 4][*action as usize % 3]
        } else {
            *action % 5
        };
        match action {
            0 => {}
            1 => {
                element.set(value.clone());
                model[index] = value.clone();
            }
            2 => {
                let same = (*element).clone();
                element.set(same);
            }
            3 => {
                *element.make_mut() = value.clone();
                model[index] = value.clone();
            }
            _ => {
                let same = model[index].clone();
                *element.make_mut() = same;
            }
        }
        seen += 1;
    }
    drop(pass);
    Ok(())
}

fn run_sweeps<T, const N: usize, U>(
    initial: Vec<T>,
    ops: Vec<Op<T>>,
    sweeps: Vec<(usize, Vec<Decision<T>>)>,
    hash_first: bool,
) -> Result<(), TestCaseError>
where
    T: Value + Debug,
    U: UpdateMap<T>,
{
    let mut list = List::<T, N, U>::try_from(initial.clone()).unwrap();
    let mut model = initial;
    // Pending pushes and writes exercise the apply-first path.
    apply_ops(&mut list, &mut model, ops);
    if hash_first {
        root(&list);
    }
    for (stop_at, decisions) in sweeps {
        let before = list.clone();
        let before_model = model.clone();
        sweep(&mut list, &mut model, stop_at, &decisions, false)?;
        check_list_matches(&list, &model)?;
        // The clone taken before the sweep did not change.
        check_list_matches(&before, &before_model)?;
        if hash_first {
            root(&list);
        }
    }
    Ok(())
}

fn run_noop_sweep<T, const N: usize, U>(
    initial: Vec<T>,
    decisions: Vec<Decision<T>>,
    hash_first: bool,
) -> Result<(), TestCaseError>
where
    T: Value + Debug,
    U: UpdateMap<T>,
{
    let mut list = List::<T, N, U>::try_from(initial.clone()).unwrap();
    if hash_first {
        root(&list);
    }
    let before = list.clone();
    let mut model = initial;
    sweep(&mut list, &mut model, usize::MAX - 1, &decisions, true)?;
    prop_assert!(list.ptr_eq(&before));
    check_list_matches(&list, &model)
}

fn sweeps<T: Debug + Clone + 'static>(
    value: impl Strategy<Value = T> + Clone + 'static,
) -> impl Strategy<Value = Vec<(usize, Vec<Decision<T>>)>> {
    vec((any::<usize>(), decisions(value)), 1..4)
}

proptest! {
    #[test]
    fn u64_sweeps(
        initial in vec(any::<u64>(), 0..40),
        ops in ops(any::<u64>()),
        sweeps in sweeps(any::<u64>()),
        hash_first in any::<bool>(),
    ) {
        run_sweeps::<u64, 64, VecMap<u64>>(initial, ops, sweeps, hash_first)?;
    }

    #[test]
    fn u64_sweeps_spanning_leaves(
        initial in vec(any::<u64>(), 0..1600),
        ops in ops(any::<u64>()),
        sweeps in sweeps(any::<u64>()),
        hash_first in any::<bool>(),
    ) {
        run_sweeps::<u64, 4096, VecMap<u64>>(initial, ops, sweeps, hash_first)?;
    }

    #[test]
    fn u64_sweeps_at_the_registry_limit(
        initial in vec(any::<u64>(), 0..1100),
        ops in ops(any::<u64>()),
        sweeps in sweeps(any::<u64>()),
        hash_first in any::<bool>(),
    ) {
        run_sweeps::<u64, { 1 << 40 }, VecMap<u64>>(initial, ops, sweeps, hash_first)?;
    }

    /// A leaf holds 4096 u8s, the widest bitset.
    #[test]
    fn u8_sweeps_with_wide_leaves(
        initial in vec(any::<u8>(), 0..4500),
        sweeps in sweeps(any::<u8>()),
        hash_first in any::<bool>(),
    ) {
        run_sweeps::<u8, 10_000, VecMap<u8>>(initial, Vec::new(), sweeps, hash_first)?;
    }

    #[test]
    fn root_sweeps(
        initial in vec(any::<[u8; 32]>(), 0..15),
        ops in ops(any::<[u8; 32]>()),
        sweeps in sweeps(any::<[u8; 32]>()),
        hash_first in any::<bool>(),
    ) {
        run_sweeps::<[u8; 32], 20, BTreeMap<usize, [u8; 32]>>(initial, ops, sweeps, hash_first)?;
    }

    #[test]
    fn item_sweeps_spanning_leaves(
        initial in vec(item(), 0..400),
        ops in ops(item()),
        sweeps in sweeps(item()),
        hash_first in any::<bool>(),
    ) {
        run_sweeps::<Item, 1024, BTreeMap<usize, Item>>(initial, ops, sweeps, hash_first)?;
    }

    #[test]
    fn blob_sweeps(
        initial in vec(blob(), 0..6),
        ops in ops(blob()),
        sweeps in sweeps(blob()),
        hash_first in any::<bool>(),
    ) {
        run_sweeps::<Blob, 9, VecMap<Blob>>(initial, ops, sweeps, hash_first)?;
    }

    #[test]
    fn u64_noop_sweep_keeps_the_tree(
        initial in vec(any::<u64>(), 0..1600),
        decisions in decisions(any::<u64>()),
        hash_first in any::<bool>(),
    ) {
        run_noop_sweep::<u64, 4096, VecMap<u64>>(initial, decisions, hash_first)?;
    }

    #[test]
    fn item_noop_sweep_keeps_the_tree(
        initial in vec(item(), 0..400),
        decisions in decisions(item()),
        hash_first in any::<bool>(),
    ) {
        run_noop_sweep::<Item, 1024, BTreeMap<usize, Item>>(initial, decisions, hash_first)?;
    }

    #[test]
    fn u64_vector_sweeps(
        initial in vec(any::<u64>(), 1500),
        decisions in decisions(any::<u64>()),
        stop_at in any::<usize>(),
        hash_first in any::<bool>(),
    ) {
        let mut vector = Vector::<u64, 1500, VecMap<u64>>::try_from(initial.clone()).unwrap();
        if hash_first {
            root(&vector);
        }
        let mut model = initial;
        let stop = stop_at % 1501;
        let mut index = 0;
        let mut pass = vector.iter_cow();
        while let Some(mut element) = pass.next_cow() {
            if index == stop {
                break;
            }
            let (action, value) = &decisions[index % decisions.len()];
            if action % 2 == 0 {
                element.set(*value);
                model[index] = *value;
            }
            index += 1;
        }
        drop(pass);
        let reference = SszVector::<u64, 1500>::try_from(model.clone()).unwrap();
        prop_assert_eq!(vector.to_vec(), model);
        prop_assert_eq!(root(&vector), root(&reference));
    }

    /// A `u64` list and an `Item` list swept in one loop, each writing from the
    /// other's element.
    #[test]
    fn lockstep_sweep_over_two_lists(
        ids in vec(any::<u64>(), 0..700),
        data in any::<[u8; 32]>(),
        hash_first in any::<bool>(),
    ) {
        let items: Vec<Item> = ids.iter().map(|&id| Item { id, data }).collect();
        let mut numbers = List::<u64, 1024, VecMap<u64>>::try_from(ids.clone()).unwrap();
        let mut list = List::<Item, 1024, BTreeMap<usize, Item>>::try_from(items.clone()).unwrap();
        if hash_first {
            root(&numbers);
            root(&list);
        }
        let mut numbers_model = ids;
        let mut items_model = items;
        {
            let mut numbers_pass = numbers.iter_cow();
            let mut items_pass = list.iter_cow();
            while let (Some(mut number), Some(mut item)) =
                (numbers_pass.next_cow(), items_pass.next_cow())
            {
                let index = number.index();
                prop_assert_eq!(index, item.index());
                if index % 3 == 0 {
                    number.set(item.id.wrapping_add(1));
                    numbers_model[index] = items_model[index].id.wrapping_add(1);
                }
                if index % 2 == 0 {
                    item.make_mut().id = *number;
                    items_model[index].id = numbers_model[index];
                }
            }
        }
        check_list_matches(&numbers, &numbers_model)?;
        check_list_matches(&list, &items_model)?;
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
