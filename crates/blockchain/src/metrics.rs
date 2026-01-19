//! Prometheus metrics for the blockchain module.

pub fn update_head_slot(slot: u64) {
    static LEAN_HEAD_SLOT: std::sync::LazyLock<prometheus::IntGauge> =
        std::sync::LazyLock::new(|| {
            prometheus::register_int_gauge!("lean_head_slot", "Latest slot of the lean chain")
                .unwrap()
        });
    LEAN_HEAD_SLOT.set(slot.try_into().unwrap());
}

pub fn update_latest_justified_slot(slot: u64) {
    static LEAN_LATEST_JUSTIFIED_SLOT: std::sync::LazyLock<prometheus::IntGauge> =
        std::sync::LazyLock::new(|| {
            prometheus::register_int_gauge!(
                "lean_latest_justified_slot",
                "Latest justified slot"
            )
            .unwrap()
        });
    LEAN_LATEST_JUSTIFIED_SLOT.set(slot.try_into().unwrap());
}

pub fn update_latest_finalized_slot(slot: u64) {
    static LEAN_LATEST_FINALIZED_SLOT: std::sync::LazyLock<prometheus::IntGauge> =
        std::sync::LazyLock::new(|| {
            prometheus::register_int_gauge!(
                "lean_latest_finalized_slot",
                "Latest finalized slot"
            )
            .unwrap()
        });
    LEAN_LATEST_FINALIZED_SLOT.set(slot.try_into().unwrap());
}

pub fn update_current_slot(slot: u64) {
    static LEAN_CURRENT_SLOT: std::sync::LazyLock<prometheus::IntGauge> =
        std::sync::LazyLock::new(|| {
            prometheus::register_int_gauge!(
                "lean_current_slot",
                "Current slot of the lean chain"
            )
            .unwrap()
        });
    LEAN_CURRENT_SLOT.set(slot.try_into().unwrap());
}

pub fn update_validators_count(count: u64) {
    static LEAN_VALIDATORS_COUNT: std::sync::LazyLock<prometheus::IntGauge> =
        std::sync::LazyLock::new(|| {
            prometheus::register_int_gauge!(
                "lean_validators_count",
                "Number of validators managed by a node"
            )
            .unwrap()
        });
    LEAN_VALIDATORS_COUNT.set(count.try_into().unwrap());
}

pub fn update_safe_target_slot(slot: u64) {
    static LEAN_SAFE_TARGET_SLOT: std::sync::LazyLock<prometheus::IntGauge> =
        std::sync::LazyLock::new(|| {
            prometheus::register_int_gauge!("lean_safe_target_slot", "Safe target slot").unwrap()
        });
    LEAN_SAFE_TARGET_SLOT.set(slot.try_into().unwrap());
}
