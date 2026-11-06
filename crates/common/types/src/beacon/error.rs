//! The crate's error type.
//!
//! The specification expresses validity conditions as `assert` statements. Each
//! one becomes an [`Error::SpecAssert`] carrying the condition it checked, which
//! keeps the enum small while still naming the failing rule in test output. The
//! structured variants exist for conditions worth inspecting programmatically
//! or worth reporting with their values.

use crate::beacon::fork::ForkName;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A validity condition from the specification did not hold. The message is
    /// the condition, phrased as the spec phrases it.
    #[error("spec assertion failed: {0}")]
    SpecAssert(&'static str),

    /// A function that the specification introduces in a later fork was called
    /// on an earlier state.
    #[error("{function} does not exist in {fork}")]
    UnsupportedForFork {
        function: &'static str,
        fork: ForkName,
    },

    #[error("index {index} out of bounds, length {len}")]
    IndexOutOfBounds { index: usize, len: usize },

    #[error("no validator at index {0}")]
    UnknownValidator(u64),

    #[error("arithmetic overflow in {0}")]
    ArithmeticOverflow(&'static str),

    #[error("signature verification failed for {0}")]
    InvalidSignature(&'static str),

    #[error("SSZ decoding failed: {0:?}")]
    SszDecode(libssz::DecodeError),

    /// A bounded SSZ collection was given more elements than its type permits.
    #[error("SSZ type error: {0:?}")]
    SszType(libssz_types::TypeError),
}

impl From<libssz::DecodeError> for Error {
    fn from(err: libssz::DecodeError) -> Self {
        Error::SszDecode(err)
    }
}

impl From<libssz_types::TypeError> for Error {
    fn from(err: libssz_types::TypeError) -> Self {
        Error::SszType(err)
    }
}

/// Returns `Err(Error::SpecAssert)` unless `condition` holds.
///
/// Mirrors the specification's `assert` statements, so a reader can match the
/// implementation against the spec line by line.
pub fn verify(condition: bool, what: &'static str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(Error::SpecAssert(what))
    }
}
