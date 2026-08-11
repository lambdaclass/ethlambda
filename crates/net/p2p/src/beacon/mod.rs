//! Ethereum mainnet's wire: topic names, req/resp protocol ids, ENR entries,
//! bootnodes, and fork-aware decode.
//!
//! Nothing here is shared with lean. What *is* shared is one layer down: the
//! discv5 stack in [`crate::discovery`], the `ssz_snappy` framing in
//! [`crate::req_resp::encoding`], and `compute_message_id` in [`crate`], all of
//! which are the beacon spec's to begin with.

pub mod bootnodes;
pub mod messages;
pub mod protocols;
pub mod topics;

/// Beacon-chain networking constants.
///
/// `ethlambda_types::beacon::config` deliberately carries no networking values
/// (see its module doc), so subnet counts and the custody requirement live with
/// the code that reads them.
pub mod constants {
    /// `ATTESTATION_SUBNET_COUNT`. The `attnets` bitfield is this wide even
    /// though this node subscribes to none of them.
    pub const ATTESTATION_SUBNET_COUNT: u64 = 64;

    /// `SYNC_COMMITTEE_SUBNET_COUNT`. The width of `MetaData`'s `syncnets`.
    pub const SYNC_COMMITTEE_SUBNET_COUNT: usize = 4;

    /// `CUSTODY_REQUIREMENT`. Advertised in the `cgc` ENR entry and in
    /// `MetaData` v3 even though nothing is custodied until data availability
    /// lands: peers may reject a lower value outright, which would defeat the
    /// mode.
    pub const CUSTODY_REQUIREMENT: u64 = 4;
}
