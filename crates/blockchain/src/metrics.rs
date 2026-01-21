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
            prometheus::register_int_gauge!("lean_latest_justified_slot", "Latest justified slot")
                .unwrap()
        });
    LEAN_LATEST_JUSTIFIED_SLOT.set(slot.try_into().unwrap());
}

pub fn update_latest_finalized_slot(slot: u64) {
    static LEAN_LATEST_FINALIZED_SLOT: std::sync::LazyLock<prometheus::IntGauge> =
        std::sync::LazyLock::new(|| {
            prometheus::register_int_gauge!("lean_latest_finalized_slot", "Latest finalized slot")
                .unwrap()
        });
    LEAN_LATEST_FINALIZED_SLOT.set(slot.try_into().unwrap());
}

pub fn update_current_slot(slot: u64) {
    static LEAN_CURRENT_SLOT: std::sync::LazyLock<prometheus::IntGauge> =
        std::sync::LazyLock::new(|| {
            prometheus::register_int_gauge!("lean_current_slot", "Current slot of the lean chain")
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

pub fn set_node_info(name: &str, version: &str) {
    static LEAN_NODE_INFO: std::sync::LazyLock<prometheus::IntGaugeVec> =
        std::sync::LazyLock::new(|| {
            prometheus::register_int_gauge_vec!(
                "lean_node_info",
                "Node information (always 1)",
                &["name", "version"]
            )
            .unwrap()
        });
    LEAN_NODE_INFO.with_label_values(&[name, version]).set(1);
}

pub fn set_node_start_time() {
    static LEAN_NODE_START_TIME_SECONDS: std::sync::LazyLock<prometheus::IntGauge> =
        std::sync::LazyLock::new(|| {
            prometheus::register_int_gauge!(
                "lean_node_start_time_seconds",
                "Timestamp when node started"
            )
            .unwrap()
        });
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    LEAN_NODE_START_TIME_SECONDS.set(timestamp as i64);
}
