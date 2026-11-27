//! The signals that stop the node: SIGINT (ctrl-c) and, on Unix, SIGTERM,
//! which is what `docker stop`, systemd and Kubernetes send.
//!
//! The first one starts a graceful shutdown. Three more, of either kind, end
//! the process with `exit(1)` rather than leave it stuck on an actor that
//! hangs in `stop()`/`join()`.
//!
//! Listening starts once the node has started (`wait_for_shutdown`,
//! `run_test_driver`), not at the top of `run_node`. Until then both signals
//! keep their default action: they end the process at once, except as PID 1
//! in a container, where they are ignored. Listening from the top would latch
//! a signal sent during startup, but it would also hold a ctrl-c sent during a
//! long checkpoint sync until startup finished, since nothing in startup gives
//! up on a signal.
//!
//! The validator client listens from the top of `validator::run` instead, and
//! a signal during its startup ends it at once, from a task of its own
//! (`validator::listen_for_stop`). It can: until startup is done nothing is
//! signed and the keymanager has taken no request, so there is nothing to
//! drain.

#[cfg(unix)]
use tokio::signal::unix::{Signal, SignalKind, signal};
use tracing::{info, warn};

/// How many signals after the first one force the process to exit.
const SIGNALS_TO_FORCE_EXIT: u32 = 3;

/// A listener for SIGINT and SIGTERM.
///
/// Both are listened for from [`ShutdownSignals::listen`] on, and one that
/// arrives before [`ShutdownSignals::recv`] runs is held until it does. From
/// then on neither signal ends the process by itself, for the life of the
/// process: tokio never uninstalls a handler. That is why the repeats that
/// force an exit are counted here ([`ShutdownSignals::force_exit_on_repeats`])
/// rather than left to the signal's default action.
pub(crate) struct ShutdownSignals {
    #[cfg(unix)]
    interrupt: Option<Signal>,
    #[cfg(unix)]
    terminate: Option<Signal>,
}

impl ShutdownSignals {
    /// Start listening. A signal that cannot be listened for is warned about
    /// once, here, and keeps its default action.
    pub(crate) fn listen() -> Self {
        Self {
            #[cfg(unix)]
            interrupt: listen_for(SignalKind::interrupt(), "SIGINT"),
            #[cfg(unix)]
            terminate: listen_for(SignalKind::terminate(), "SIGTERM"),
        }
    }

    /// Wait for the next SIGINT or SIGTERM, and name it.
    ///
    /// Only a delivered signal returns. A signal that is not listened for, or
    /// whose stream has ended (its runtime is shutting down), never does.
    #[cfg(unix)]
    pub(crate) async fn recv(&mut self) -> &'static str {
        tokio::select! {
            Some(()) = next(&mut self.interrupt) => "SIGINT",
            Some(()) = next(&mut self.terminate) => "SIGTERM",
            else => std::future::pending().await,
        }
    }

    /// Wait for the next ctrl-c, the only one of the two outside Unix.
    #[cfg(not(unix))]
    pub(crate) async fn recv(&mut self) -> &'static str {
        if let Err(err) = tokio::signal::ctrl_c().await {
            warn!(%err, "Cannot listen for ctrl-c");
            std::future::pending::<()>().await;
        }
        "SIGINT"
    }

    /// Spawn a task that counts the signals still to come, once a graceful
    /// shutdown has started, and calls `exit(1)` on the
    /// [`SIGNALS_TO_FORCE_EXIT`]th.
    ///
    /// Either signal counts, so `kill <pid>` after a ctrl-c that hung counts
    /// toward the exit just as another ctrl-c does.
    pub(crate) fn force_exit_on_repeats(mut self) {
        tokio::spawn(async move {
            for remaining in (1..SIGNALS_TO_FORCE_EXIT).rev() {
                let signal = self.recv().await;
                warn!(
                    signal,
                    "Graceful shutdown in progress. Send {remaining} more ctrl-c or SIGTERM to force ungraceful shutdown"
                );
            }
            let signal = self.recv().await;
            info!(signal, "Forced ungraceful shutdown...");
            std::process::exit(1);
        });
    }
}

#[cfg(unix)]
fn listen_for(kind: SignalKind, name: &'static str) -> Option<Signal> {
    signal(kind)
        .inspect_err(|err| {
            warn!(
                %err,
                signal = name,
                "Cannot listen for this signal; it will not shut the node down gracefully"
            )
        })
        .ok()
}

/// The next delivery of `signal`, or `None` when it is not listened for or
/// its stream has ended.
#[cfg(unix)]
async fn next(signal: &mut Option<Signal>) -> Option<()> {
    signal.as_mut()?.recv().await
}
