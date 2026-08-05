//! The Ethereum consensus spec test suites.
//!
//! One integration binary holds every runner, so the fixture harness in
//! [`spec`] is compiled once and each runner lives in its own file with a single
//! owner. Add a runner by adding a module here.
//!
//! Run with `make test-beacon`, which downloads the fixtures and builds the
//! crate once per preset.

mod spec;
