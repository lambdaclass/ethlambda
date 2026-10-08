//! The lean consensus chain's wire: protocol ids, containers, and encoding.
//!
//! The counterpart of [`crate::beacon`], and deliberately the same shape. What
//! is *not* here is as telling as what is: there is no dispatch and no handler,
//! because a message is dispatched and handled the same way whichever chain it
//! arrived from. `crate::req_resp` owns that path, and reaches into this module
//! and `crate::beacon` only where the two wires genuinely differ, which is
//! encoding.

pub mod encoding;
pub mod messages;
pub mod protocols;
