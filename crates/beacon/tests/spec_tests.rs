//! The Ethereum consensus spec test suites.
//!
//! One integration binary holds every runner, so the fixture harness in
//! [`spec`] is compiled once and each runner lives in its own file with a single
//! owner. Add a runner by adding a module to [`spec`] and one line below.
//!
//! Run with `make test-beacon`, which downloads the fixtures and builds the
//! crate once per preset.
//!
//! # Why this binary supplies its own harness
//!
//! Built with `harness = false`, so [`main`] below is the entry point instead of
//! the one the `#[test]` attribute generates. The reason is that a fixture case
//! is not known until the fixture tree is walked, and `#[test]` needs its tests
//! at compile time. Under the generated harness the only thing a suite could be
//! was one test looping over its own cases, which made every failure a failure
//! of the whole suite: the name in the output was the suite's, one bad case
//! marked thousands of passing ones as part of a failed test, and a run stopped
//! reporting anything per case at all.
//!
//! `libtest_mimic` takes a list of tests built at run time and otherwise behaves
//! as the standard harness does, so each case is named, counted, filtered, and
//! attributed on its own, and `--test-threads`, `--ignored`, `--list`, and a
//! plain substring filter all keep working. Every case is independent, so the
//! harness's own pool runs them concurrently, one case per work item, which is
//! finer-grained than anything a suite-per-test layout could balance.

mod spec;

fn main() {
    let args = libtest_mimic::Arguments::from_args();

    let mut trials = Vec::new();
    trials.extend(spec::harness::trials());
    trials.extend(spec::epoch_processing::trials());
    trials.extend(spec::fork::trials());
    trials.extend(spec::fork_choice::trials());
    trials.extend(spec::operations::trials());
    trials.extend(spec::rewards::trials());
    trials.extend(spec::sanity::trials());
    trials.extend(spec::shuffling::trials());
    trials.extend(spec::ssz_static::trials());
    trials.extend(spec::transition::trials());

    // The release ships genesis fixtures for the minimal preset only, so the
    // whole module is compiled out otherwise (see its own inner attribute).
    #[cfg(feature = "preset-minimal")]
    trials.extend(spec::genesis::trials());

    libtest_mimic::run(&args, trials).exit();
}
