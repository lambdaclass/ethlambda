pub mod attestation;
pub mod block;
pub mod genesis;
pub mod primitives;
pub mod signature;
pub mod state;

/// Display helper for truncated root hashes (8 hex chars)
pub struct ShortRoot<'a>(pub &'a [u8; 32]);

impl std::fmt::Display for ShortRoot<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0[..4] {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}
