//! Prometheus metrics for state transition.

use std::sync::LazyLock;

use ethlambda_metrics::*;

static LEAN_STATE_TRANSITION_SLOTS_PROCESSED_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "lean_state_transition_slots_processed_total",
        "Count of processed slots"
    )
    .unwrap()
});

static LEAN_STATE_TRANSITION_ATTESTATIONS_PROCESSED_TOTAL: LazyLock<IntCounter> =
    LazyLock::new(|| {
        register_int_counter!(
            "lean_state_transition_attestations_processed_total",
            "Count of processed attestations"
        )
        .unwrap()
    });

static LEAN_FINALIZATIONS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "lean_finalizations_total",
        "Total number of finalization attempts",
        &["result"]
    )
    .unwrap()
});

/// Increment the slots processed counter by the given amount.
pub fn inc_slots_processed(count: u64) {
    LEAN_STATE_TRANSITION_SLOTS_PROCESSED_TOTAL.inc_by(count);
}

/// Increment the attestations processed counter by the given amount.
pub fn inc_attestations_processed(count: u64) {
    LEAN_STATE_TRANSITION_ATTESTATIONS_PROCESSED_TOTAL.inc_by(count);
}

/// Increment the finalization counter with the given result.
pub fn inc_finalizations(result: &str) {
    LEAN_FINALIZATIONS_TOTAL.with_label_values(&[result]).inc();
}

static LEAN_BEACON_COMMITTEE_CACHE_LOOKUPS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "lean_beacon_committee_cache_lookups_total",
        "Beacon committee shuffling lookups, by whether the committee cache served them",
        &["result"]
    )
    .unwrap()
});

/// Count one `CommitteeCache` lookup: `hit`, `miss` (a whole-epoch shuffle
/// was built and cached), or `unkeyable` (built for one caller, not cached).
pub fn inc_committee_cache_lookups(result: &str) {
    LEAN_BEACON_COMMITTEE_CACHE_LOOKUPS_TOTAL
        .with_label_values(&[result])
        .inc();
}

static LEAN_BEACON_TOTAL_ACTIVE_BALANCE_LOOKUPS_TOTAL: LazyLock<IntCounterVec> =
    LazyLock::new(|| {
        register_int_counter_vec!(
            "lean_beacon_total_active_balance_lookups_total",
            "Total active balance lookups, by whether the active balance cache served them",
            &["result"]
        )
        .unwrap()
    });

/// Count one `ActiveBalanceCache` lookup: `hit`, `miss` (a registry pass was
/// run and cached), or `unkeyable` (computed for one caller, not cached).
pub fn inc_total_active_balance_lookups(result: &str) {
    LEAN_BEACON_TOTAL_ACTIVE_BALANCE_LOOKUPS_TOTAL
        .with_label_values(&[result])
        .inc();
}

static LEAN_BEACON_JUSTIFIED_BALANCES_LOOKUPS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(
    || {
        register_int_counter_vec!(
            "lean_beacon_justified_balances_lookups_total",
            "Beacon fork-choice justified-balances snapshot lookups, by whether the cached snapshot served them",
            &["result"]
        )
        .unwrap()
    },
);

/// Count one justified-balances lookup: `hit` (the cached snapshot matched the
/// justified checkpoint) or `miss` (it was rebuilt from the checkpoint state).
pub fn inc_justified_balances_lookups(result: &str) {
    LEAN_BEACON_JUSTIFIED_BALANCES_LOOKUPS_TOTAL
        .with_label_values(&[result])
        .inc();
}

static LEAN_BEACON_JUSTIFIED_BALANCES_BUILD_SECONDS: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!(
        "lean_beacon_justified_balances_build_seconds",
        "Duration of one justified-balances snapshot build (one pass over the checkpoint state's registry)",
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
    )
    .unwrap()
});

/// Time one justified-balances snapshot build, excluding the checkpoint state
/// lookup it starts from.
pub fn time_justified_balances_build() -> TimingGuard {
    TimingGuard::new(&LEAN_BEACON_JUSTIFIED_BALANCES_BUILD_SECONDS)
}

static LEAN_BEACON_EPOCH_PRECOMPUTE_LOOKUPS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "lean_beacon_epoch_precompute_lookups_total",
        "Epoch-crossing block imports, by whether a precomputed epoch-boundary state was cached",
        &["result"]
    )
    .unwrap()
});

/// Count one epoch-crossing import's lookup of a precomputed state: `hit` or
/// `miss`.
pub fn inc_epoch_precompute_lookups(result: &str) {
    LEAN_BEACON_EPOCH_PRECOMPUTE_LOOKUPS_TOTAL
        .with_label_values(&[result])
        .inc();
}

static LEAN_BEACON_EPOCH_PRECOMPUTE_SECONDS: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!(
        "lean_beacon_epoch_precompute_seconds",
        "Duration of one epoch-transition precompute: advance, flush and hash",
        vec![0.1, 0.25, 0.5, 0.75, 1.0, 1.5, 2.0, 3.0, 4.0, 8.0]
    )
    .unwrap()
});

/// Start timing one epoch precompute. Records duration when the guard is dropped.
pub fn time_epoch_precompute() -> TimingGuard {
    TimingGuard::new(&LEAN_BEACON_EPOCH_PRECOMPUTE_SECONDS)
}

static LEAN_BEACON_EPOCH_PRECOMPUTE_STARTED_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "lean_beacon_epoch_precompute_started_total",
        "Epoch precompute workers started, by what triggered them",
        &["trigger"]
    )
    .unwrap()
});

/// Count one precompute worker started: `head` (a last-slot block became head)
/// or `timer` (three quarters into a last slot with nothing computed).
pub fn inc_epoch_precompute_started(trigger: &str) {
    LEAN_BEACON_EPOCH_PRECOMPUTE_STARTED_TOTAL
        .with_label_values(&[trigger])
        .inc();
}

// --- Beacon state transition phases ---

/// Declares [`StfPhase`], its label, [`StfPhase::ALL`] and
/// [`BEACON_STF_PHASES`] from one list, so a phase cannot exist in the code
/// without being in the declared label set or the other way round.
macro_rules! stf_phases {
    ($($(#[$doc:meta])* $variant:ident => $label:literal,)+) => {
        /// A step of the beacon state transition that
        /// `lean_beacon_stf_phase_seconds` times.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum StfPhase {
            $($(#[$doc])* $variant,)+
        }

        impl StfPhase {
            /// Every phase, in declaration order.
            pub const ALL: &'static [StfPhase] = &[$(StfPhase::$variant,)+];

            /// The `phase` label value this phase is observed under.
            pub const fn label(self) -> &'static str {
                match self {
                    $(StfPhase::$variant => $label,)+
                }
            }
        }

        /// The `phase` label values of `lean_beacon_stf_phase_seconds`, in the
        /// order a block crosses them. Generated from [`StfPhase`], so it is
        /// the only list there is.
        pub const BEACON_STF_PHASES: &[&str] = &[$($label,)+];
    };
}

stf_phases! {
    /// Advancing the state to the block's slot, everything but the epoch
    /// work: per-slot root bookkeeping, the fork upgrade and the closing
    /// flush.
    ProcessSlots => "process_slots",
    /// One observation per epoch boundary crossed (a long skip crosses
    /// several).
    ProcessEpoch => "process_epoch",
    /// The proposer's signature over the block, when the caller asked for it.
    BlockSignature => "block_signature",
    BlockHeader => "block_header",
    Randao => "randao",
    Eth1Data => "eth1_data",
    /// Withdrawals and the execution payload; gloas: the parent payload, the
    /// withdrawals and the bid.
    ExecutionPayload => "execution_payload",
    ProposerSlashings => "proposer_slashings",
    AttesterSlashings => "attester_slashings",
    Attestations => "attestations",
    Deposits => "deposits",
    VoluntaryExits => "voluntary_exits",
    BlsToExecutionChanges => "bls_to_execution_changes",
    ExecutionRequests => "execution_requests",
    PayloadAttestations => "payload_attestations",
    SyncAggregate => "sync_aggregate",
    /// The post-state flush and `hash_tree_root` that checks
    /// `block.state_root`.
    StateRoot => "state_root",
}

/// Which caller a beacon STF observation is charged to.
///
/// The epoch precompute worker runs `process_epoch` on another thread while an
/// import is running, and the import replay reads this histogram before and
/// after every block, so one global series would charge the worker's seconds
/// to whichever block happened to be importing. Observations therefore carry
/// the context of the thread that made them: only a thread inside an
/// [`import_context`] guard writes `import`, and every other caller (the
/// precompute worker, checkpoint-state advances, block production, gossip
/// validation, the spec runners) writes `other`.
///
/// A thread-local rather than a parameter because the phases are observed deep
/// inside the per-fork block processing, and the context is a property of who
/// asked for the transition, which none of those functions know. Every
/// observation is made on the calling thread, never inside a rayon task, so
/// the thread-local is the right scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StfContext {
    Import,
    Other,
}

impl StfContext {
    const fn label(self) -> &'static str {
        match self {
            StfContext::Import => STF_CONTEXT_IMPORT,
            StfContext::Other => "other",
        }
    }
}

thread_local! {
    static STF_CONTEXT: std::cell::Cell<StfContext> =
        const { std::cell::Cell::new(StfContext::Other) };
}

/// The `context` label value of the block import path, for readers of the
/// histogram.
pub const STF_CONTEXT_IMPORT: &str = "import";

/// Keeps the current thread's STF observations in the `import` series until
/// dropped, then restores whatever context it replaced.
#[must_use = "the guard is the scope of the import context"]
pub struct ImportContextGuard {
    previous: StfContext,
}

impl Drop for ImportContextGuard {
    fn drop(&mut self) {
        STF_CONTEXT.with(|context| context.set(self.previous));
    }
}

/// Charge this thread's STF phase observations to block import until the
/// returned guard is dropped. See [`StfContext`].
pub fn import_context() -> ImportContextGuard {
    let previous = STF_CONTEXT.with(|context| context.replace(StfContext::Import));
    ImportContextGuard { previous }
}

static LEAN_BEACON_STF_PHASE_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        "lean_beacon_stf_phase_seconds",
        "Time one step of the beacon state transition took, per observation. `phase` is one of \
         BEACON_STF_PHASES; `context` is `import` for the block import path and `other` for \
         every other caller (epoch precompute, checkpoint states, block production, gossip \
         validation). A step that did not run writes nothing, and a step that runs more than \
         once in a transition (process_epoch across a long skip) writes once per run.",
        &["context", "phase"],
        vec![
            0.0001, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 4.0
        ]
    )
    .unwrap()
});

#[cfg(test)]
thread_local! {
    /// What this thread observed, as `(context, phase)`. The histogram is
    /// process-global and the lib tests run in parallel, so a test reading
    /// series deltas would count its neighbours' observations; each thread's
    /// own log cannot be written by anyone else.
    static OBSERVATION_LOG: std::cell::RefCell<Vec<(&'static str, StfPhase)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Drain this thread's observation log.
#[cfg(test)]
pub fn take_observation_log() -> Vec<(&'static str, StfPhase)> {
    OBSERVATION_LOG.with(|log| std::mem::take(&mut *log.borrow_mut()))
}

/// Record `elapsed` against `phase` in the calling thread's context.
pub fn observe_stf_phase(phase: StfPhase, elapsed: std::time::Duration) {
    let context = STF_CONTEXT.with(|context| context.get());
    #[cfg(test)]
    OBSERVATION_LOG.with(|log| log.borrow_mut().push((context.label(), phase)));
    LEAN_BEACON_STF_PHASE_SECONDS
        .with_label_values(&[context.label(), phase.label()])
        .observe(elapsed.as_secs_f64());
}

/// Run `step`, observing its duration as `phase`: one `Instant` pair, however
/// long the step.
///
/// A step that fails inside `step` is observed too, since the closure returns
/// before the observation. That is deliberate: a rejected block's cost is
/// still cost.
pub fn timed<T>(phase: StfPhase, step: impl FnOnce() -> T) -> T {
    let started = std::time::Instant::now();
    let result = step();
    observe_stf_phase(phase, started.elapsed());
    result
}

/// Run `step` over every item of `items`, stopping at the first error, and
/// observe the whole loop as one `phase` observation.
///
/// An empty list observes nothing: a block with no deposits did not run the
/// deposits step, which is a different statement from a step that took no
/// time. The timer starts at the first item rather than before the iterator is
/// built, so it does not charge the list's own construction.
pub fn try_for_each_timed<I, E>(
    phase: StfPhase,
    items: I,
    mut step: impl FnMut(I::Item) -> Result<(), E>,
) -> Result<(), E>
where
    I: IntoIterator,
{
    let mut started = None;
    let mut outcome = Ok(());
    for item in items {
        started.get_or_insert_with(std::time::Instant::now);
        outcome = step(item);
        if outcome.is_err() {
            break;
        }
    }
    if let Some(started) = started {
        observe_stf_phase(phase, started.elapsed());
    }
    outcome
}

static LEAN_STATE_TRANSITION_TIME_SECONDS: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!(
        "lean_state_transition_time_seconds",
        "Duration of the entire state transition",
        vec![0.25, 0.5, 0.75, 1.0, 1.25, 1.5, 2.0, 2.5, 3.0, 4.0]
    )
    .unwrap()
});

static LEAN_STATE_TRANSITION_SLOTS_PROCESSING_TIME_SECONDS: LazyLock<Histogram> =
    LazyLock::new(|| {
        register_histogram!(
            "lean_state_transition_slots_processing_time_seconds",
            "Duration to process slots",
            vec![0.005, 0.01, 0.025, 0.05, 0.1, 1.0]
        )
        .unwrap()
    });

static LEAN_STATE_TRANSITION_BLOCK_PROCESSING_TIME_SECONDS: LazyLock<Histogram> =
    LazyLock::new(|| {
        register_histogram!(
            "lean_state_transition_block_processing_time_seconds",
            "Duration to process a block in state transition",
            vec![0.005, 0.01, 0.025, 0.05, 0.1, 1.0]
        )
        .unwrap()
    });

static LEAN_STATE_TRANSITION_ATTESTATIONS_PROCESSING_TIME_SECONDS: LazyLock<Histogram> =
    LazyLock::new(|| {
        register_histogram!(
            "lean_state_transition_attestations_processing_time_seconds",
            "Duration to process attestations",
            vec![0.005, 0.01, 0.025, 0.05, 0.1, 1.0]
        )
        .unwrap()
    });

/// Start timing state transition. Records duration when the guard is dropped.
pub fn time_state_transition() -> TimingGuard {
    TimingGuard::new(&LEAN_STATE_TRANSITION_TIME_SECONDS)
}

/// Start timing slots processing. Records duration when the guard is dropped.
pub fn time_slots_processing() -> TimingGuard {
    TimingGuard::new(&LEAN_STATE_TRANSITION_SLOTS_PROCESSING_TIME_SECONDS)
}

/// Start timing block processing. Records duration when the guard is dropped.
pub fn time_block_processing() -> TimingGuard {
    TimingGuard::new(&LEAN_STATE_TRANSITION_BLOCK_PROCESSING_TIME_SECONDS)
}

/// Start timing attestations processing. Records duration when the guard is dropped.
pub fn time_attestations_processing() -> TimingGuard {
    TimingGuard::new(&LEAN_STATE_TRANSITION_ATTESTATIONS_PROCESSING_TIME_SECONDS)
}

static LEAN_DATA_COLUMN_KZG_VERIFY_SECONDS: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!(
        "lean_data_column_kzg_verify_seconds",
        "Time spent batch-verifying one sidecar's cells against its own commitments",
        vec![0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
    )
    .unwrap()
});

/// Start timing a sidecar's KZG cell-proof batch. Records duration when the
/// guard is dropped.
///
/// Here rather than beside the rest of the column metrics, because the batch
/// runs inside `beacon::gossip::column`'s rules, which both the gossip path
/// and the p2p layer's chain checks call.
pub fn time_data_column_kzg_verify() -> TimingGuard {
    TimingGuard::new(&LEAN_DATA_COLUMN_KZG_VERIFY_SECONDS)
}

/// Register the metrics above that should be visible before their first
/// observation.
pub fn init() {
    LazyLock::force(&LEAN_DATA_COLUMN_KZG_VERIFY_SECONDS);
    LazyLock::force(&LEAN_BEACON_STF_PHASE_SECONDS);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_label_list_is_the_enum() {
        let labels: Vec<&str> = StfPhase::ALL.iter().map(|phase| phase.label()).collect();
        assert_eq!(labels, BEACON_STF_PHASES);

        let mut unique = labels.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), labels.len(), "a label is declared twice");
    }

    #[test]
    fn only_a_thread_inside_the_guard_writes_the_import_series() {
        take_observation_log();
        let phase = StfPhase::ProposerSlashings;

        timed(phase, || ());
        {
            let _guard = import_context();
            timed(phase, || ());
            // A thread spawned inside the guard (the precompute worker's
            // situation) does not inherit it.
            let spawned = std::thread::spawn(move || {
                timed(phase, || ());
                take_observation_log()
            })
            .join()
            .unwrap();
            assert_eq!(spawned, [("other", phase)]);
        }
        timed(phase, || ());

        assert_eq!(
            take_observation_log(),
            [("other", phase), ("import", phase), ("other", phase)]
        );
    }

    #[test]
    fn a_nested_guard_restores_the_context_it_replaced() {
        take_observation_log();
        let phase = StfPhase::Deposits;
        let outer = import_context();
        drop(import_context());
        timed(phase, || ());
        drop(outer);
        timed(phase, || ());
        assert_eq!(
            take_observation_log(),
            [("import", phase), ("other", phase)]
        );
    }

    #[test]
    fn an_empty_list_observes_nothing_and_a_failure_stops_the_loop() {
        take_observation_log();
        let phase = StfPhase::VoluntaryExits;

        let empty: [u8; 0] = [];
        try_for_each_timed(phase, empty, |_| Ok::<(), ()>(())).unwrap();
        assert!(
            take_observation_log().is_empty(),
            "an empty list ran no step"
        );

        let mut seen = 0;
        let outcome = try_for_each_timed(phase, [1, 2, 3], |item| {
            seen += 1;
            if item == 2 { Err("second") } else { Ok(()) }
        });
        assert_eq!(outcome, Err("second"));
        assert_eq!(seen, 2, "items after the failure are not run");
        assert_eq!(
            take_observation_log(),
            [("other", phase)],
            "one observation per loop"
        );
    }
}
