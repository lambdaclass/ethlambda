//! The JSON a `replay-era` run leaves behind for CI to archive.

use serde::Serialize;

/// What one end-of-era check concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Outcome {
    Passed,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct OracleCheck {
    pub(super) name: &'static str,
    pub(super) outcome: Outcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) detail: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct EraReport {
    pub(super) network: String,
    pub(super) era: u64,
    pub(super) blocks_applied: u64,
    /// Blocks in the file at or below the starting state's slot, which the
    /// state already includes.
    pub(super) blocks_already_in_state: u64,
    pub(super) skipped_empty_slots: u64,
    /// Wall time for the whole era: decoding, blocks and the oracle.
    pub(super) elapsed_secs: f64,
    /// Wall time spent applying blocks (decode plus state transition).
    pub(super) apply_secs: f64,
    pub(super) mean_ms_per_block: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) max_blocks: Option<u64>,
    pub(super) oracle: Vec<OracleCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) error: Option<String>,
}

impl EraReport {
    pub(super) fn new(network: &str, era: u64, max_blocks: Option<u64>) -> Self {
        Self {
            network: network.to_string(),
            era,
            blocks_applied: 0,
            blocks_already_in_state: 0,
            skipped_empty_slots: 0,
            elapsed_secs: 0.0,
            apply_secs: 0.0,
            mean_ms_per_block: 0.0,
            max_blocks,
            oracle: Vec::new(),
            error: None,
        }
    }

    pub(super) fn check(&mut self, name: &'static str, outcome: Outcome, detail: Option<String>) {
        self.oracle.push(OracleCheck {
            name,
            outcome,
            detail,
        });
    }
}
