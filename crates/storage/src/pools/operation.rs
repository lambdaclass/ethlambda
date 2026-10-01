//! Proposer slashings, attester slashings, voluntary exits and BLS changes
//! this node has validated, held until a block packs them.

/// Filled in by the operation-pool task; empty until then.
#[derive(Debug, Default)]
pub struct OperationPool {}
