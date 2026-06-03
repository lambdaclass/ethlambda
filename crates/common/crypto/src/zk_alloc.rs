//! Proving-scoped integration of leanVM's `zk-alloc` arena allocator.
//!
//! **Benchmark build only** (`zk-alloc` feature). The goal is to get leanVM's
//! bump-arena speedup for XMSS aggregation without destabilizing a long-running
//! node.
//!
//! # Why a dispatcher instead of installing `ZkAllocator` directly
//!
//! `ZkAllocator` is a *process-global* bump-arena: [`begin_phase`] flips a global
//! switch and resets every thread's slab. leanVM's own binary is safe because it
//! does nothing but prove between `begin_phase`/`end_phase`. ethlambda is not:
//! the tokio runtime, p2p, storage, and actor threads allocate continuously. Any
//! long-lived buffer one of them allocates during a phase would be silently
//! overwritten by the next phase's slab reset.
//!
//! [`ScopedZkAlloc`] is a `#[global_allocator]` that routes to the arena **only on
//! threads explicitly marked as proving**: the global rayon pool's workers, which
//! leanVM's prover uses exclusively (ethlambda itself never touches the global
//! pool). The pool is built at startup via [`init_arena_rayon_pool`] with a
//! `start_handler` that permanently flags each worker. Every other thread —
//! tokio, p2p, storage, the actor thread — always uses the system allocator, so
//! its allocations are never reset. The prover *caller* is also unflagged: only
//! the parallel work inside leanVM lands in the arena, and the assembled proof
//! itself lands in System.
//!
//! Two earlier designs failed and inform this one:
//! - Marking the global pool's workers with `rayon::broadcast` around each phase
//!   deadlocked the node: broadcast left the pool's sleep/wakeup accounting in a
//!   state where the prover's injected work was never stolen.
//! - A dedicated `install`-target pool crashed on the second proof: rayon's and
//!   crossbeam's long-lived internals (epoch participants, work-stealing deque
//!   buffers) were first allocated *inside* a phase, in arena memory the next
//!   phase's slab reset corrupted (`crossbeam_epoch::try_advance` UAF, then
//!   rayon `AbortIfPanic`). The global pool avoids this because `setup_prover`
//!   runs heavy parallel work on it *before any phase exists*, growing those
//!   internals to near-peak size in System memory — the same warmup leanVM's
//!   own binaries rely on.
//!
//! Two conditions gate an arena allocation: the thread-local [`USE_ARENA`] flag
//! **and** leanVM's global `ARENA_ACTIVE` (checked inside `ZkAllocator::alloc`,
//! set by `begin_phase`). So even on a flagged thread, anything allocated outside
//! a phase — prover setup, input decompression, output serialization — lands in
//! the system allocator.
//!
//! # Accepted limitations
//!
//! - jemalloc and its `/debug/pprof` heap endpoints are gone in this build:
//!   `ZkAllocator::dealloc` forwards non-arena frees to `std::alloc::System`, so
//!   the non-proving path must be `System` (libc), not jemalloc, or we would free
//!   a jemalloc pointer with libc `free`.
//! - All proving is serialized behind [`PROVING`]; concurrent aggregation (the
//!   spawn_blocking worker vs. actor-thread block building) blocks rather than
//!   running in parallel. Acceptable for a benchmark; it also prevents the
//!   `begin_phase` nesting panic.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::{Mutex, MutexGuard, Once};

use lean_multisig::{ZkAllocator, begin_phase, end_phase};

/// Re-exported so the binary can run leanVM's startup core-count assertion.
pub use lean_multisig::init_allocator;

thread_local! {
    /// Marks the current thread as a proving thread. While set *and* a phase is
    /// active, this thread's allocations route to leanVM's arena; otherwise to
    /// the system allocator.
    static USE_ARENA: Cell<bool> = const { Cell::new(false) };
}

/// Serializes every entry into the leanVM prover so phases never nest and
/// `ARENA_ACTIVE` is only ever true for one thread group at a time.
pub static PROVING: Mutex<()> = Mutex::new(());

/// Global allocator that confines leanVM's arena to proving threads.
pub struct ScopedZkAlloc;

// SAFETY: every returned pointer comes from either `ZkAllocator` (which yields
// arena memory only while a phase is active, System otherwise) or `System`
// directly. `dealloc` always defers to `ZkAllocator::dealloc`, which is
// address-based — arena pointers are a no-op, all others forward to System —
// so it correctly frees pointers produced by either path, from any thread.
unsafe impl GlobalAlloc for ScopedZkAlloc {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if USE_ARENA.get() {
            unsafe { ZkAllocator.alloc(layout) }
        } else {
            unsafe { System.alloc(layout) }
        }
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if USE_ARENA.get() {
            unsafe { ZkAllocator.alloc_zeroed(layout) }
        } else {
            unsafe { System.alloc_zeroed(layout) }
        }
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { ZkAllocator.dealloc(ptr, layout) };
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // Must NOT defer to `ZkAllocator::realloc`: on growth it calls its own
        // `alloc`, which gates on the global `ARENA_ACTIVE` rather than our
        // thread-local flag, which would leak arena memory onto non-proving
        // threads. Route through our own thread-gated alloc/dealloc instead.
        if new_size <= layout.size() {
            // Shrink in place; the existing block is large enough. Matches
            // `ZkAllocator`'s behaviour and is valid for arena and System
            // pointers alike.
            return ptr;
        }
        let new_layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
        let new_ptr = unsafe { self.alloc(new_layout) };
        if !new_ptr.is_null() {
            unsafe { std::ptr::copy_nonoverlapping(ptr, new_ptr, layout.size()) };
            unsafe { self.dealloc(ptr, layout) };
        }
        new_ptr
    }
}

/// Build the **global** rayon pool with arena-flagged workers. Must run before
/// anything else initializes the global pool (leanVM's `setup_prover` is the
/// first rayon user in ethlambda). Idempotent. If the pool was already built by
/// someone else, its workers stay unflagged and proving simply falls back to the
/// system allocator — safe, just no arena speedup.
pub fn init_arena_rayon_pool() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        rayon::ThreadPoolBuilder::new()
            .thread_name(|i| format!("zk-prover-{i}"))
            .start_handler(|_| USE_ARENA.set(true))
            .build_global()
            .inspect_err(|err| {
                eprintln!(
                    "zk-alloc: global rayon pool already initialized ({err}); \
                     proving will not use the arena"
                );
            })
            .ok();
    });
}

/// Holds the [`PROVING`] lock for one prover operation, serializing all proving so
/// phases never nest. The lock is released when the session is dropped, which must
/// be *after* the proof is serialized (the proof may reference arena memory that
/// the next phase would reset).
pub(crate) struct ArenaSession {
    _lock: MutexGuard<'static, ()>,
}

impl ArenaSession {
    pub(crate) fn begin() -> Self {
        let lock = PROVING.lock().unwrap_or_else(|poison| poison.into_inner());
        Self { _lock: lock }
    }

    /// Run `produce` (the prover call) inside an arena phase. `produce` executes
    /// on the calling thread (unflagged → System); the prover's internal rayon
    /// work runs on the arena-flagged global pool workers. The returned value may
    /// reference arena memory; it is safe to read until the next `begin_phase`,
    /// which the held lock prevents.
    pub(crate) fn prove<T, F>(&self, produce: F) -> T
    where
        F: FnOnce() -> T,
    {
        begin_phase();
        // Guarantees `end_phase` runs even if the prover panics, so the global
        // arena switch is never left stuck active. leanVM's `end_phase` also
        // flushes the global pool's injector (its job blocks may live in arena).
        struct EndOnDrop;
        impl Drop for EndOnDrop {
            fn drop(&mut self) {
                end_phase();
            }
        }
        let _end = EndOnDrop;
        produce()
    }
}
