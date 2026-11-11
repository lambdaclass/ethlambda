//! The HTTP server (API, metrics and debug routes) as a supervised actor.
//!
//! The one piece of the node that restarts safely, so the one piece under a
//! supervisor. It holds no state of its own beyond what each run builds afresh
//! from cloned handles (the store, the P2P actor's protocol ref, the shared
//! pools and controllers), so a fresh instance after a failure serves what the
//! old one did. What a restart loses is per connection: open event streams end
//! and their clients reconnect, and the Beacon API's fee recipients, registered
//! through `prepare_beacon_proposer`, are forgotten until the validator client
//! sends them again, which it does every epoch.
//!
//! The chain and P2P actors are deliberately not supervised; see `run_node`.
//!
//! Before this, a server that failed logged one error and the node ran on with
//! no API and no metrics until someone restarted the process.

use std::{future::Future, io, pin::Pin, sync::Arc, time::Duration};

use spawned_concurrency::actor;
use spawned_concurrency::message::Message;
use spawned_concurrency::send_handler;
use spawned_concurrency::supervision::{
    Backoff, SupervisedChild, Supervisor, SupervisorConfig, SupervisorStrategy,
};
use spawned_concurrency::tasks::{Actor, Context, Handler};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

/// One run of the HTTP server: bind its listeners, then serve until the token
/// is cancelled. Called once per actor generation.
pub(crate) type Serve = Arc<
    dyn Fn(CancellationToken) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send>> + Send + Sync,
>;

/// The restart budget: at most three restarts a minute, the first after a
/// second and backing off to ten. A server that keeps failing faster than that
/// (its port taken by another process, say) exhausts the budget, the
/// supervisor gives up, and the node runs on without HTTP as it did before
/// supervision, with an error saying so.
pub(crate) fn supervisor_config() -> SupervisorConfig {
    SupervisorConfig {
        strategy: SupervisorStrategy::OneForOne,
        max_restarts: 3,
        restart_window: Duration::from_secs(60),
        backoff: Backoff {
            initial: Duration::from_secs(1),
            maximum: Duration::from_secs(10),
            stable_after: Duration::from_secs(60),
            ..Backoff::default()
        },
        ..SupervisorConfig::default()
    }
}

pub(crate) struct HttpServer {
    serve: Serve,
    /// Cancelled when this generation stops, so axum closes its listeners
    /// gracefully.
    shutdown: CancellationToken,
}

impl HttpServer {
    pub(crate) fn new(serve: Serve) -> Self {
        Self {
            serve,
            shutdown: CancellationToken::new(),
        }
    }
}

#[actor]
impl HttpServer {
    /// Serve on an owned helper, which the actor system cancels and joins when
    /// this generation stops, and stop the actor when the server returns: the
    /// exit is what tells the supervisor to build a fresh one.
    #[started]
    async fn start_serving(&mut self, ctx: &Context<Self>) {
        let server = (self.serve)(self.shutdown.clone());
        let owner = ctx.clone();
        let served = ctx.spawn_helper(async move {
            match server.await {
                Ok(()) => info!("HTTP server stopped serving"),
                Err(err) => error!(%err, "HTTP server failed"),
            }
            // A stopped Permanent child is restarted while its supervisor is
            // open. During node shutdown this generation is already stopping
            // and nothing restarts it.
            owner.stop();
        });
        if let Err(err) = served {
            warn!(%err, "Could not start the HTTP server");
            ctx.stop();
        }
    }

    #[stopped]
    async fn stop_serving(&mut self, _ctx: &Context<Self>) {
        self.shutdown.cancel();
    }
}

/// Fault injection only: crash the HTTP server as a panicking handler would.
/// Sent by [`install_fault_injection`], never by the node itself.
pub(crate) struct InjectCrash;

impl Message for InjectCrash {
    type Result = ();
}

#[send_handler]
impl Handler<InjectCrash> for HttpServer {
    async fn handle(&mut self, _msg: InjectCrash, _ctx: &Context<Self>) {
        panic!("fault injection: crashing the HTTP server");
    }
}

/// Log every restart of the supervised HTTP server, and the supervisor giving
/// up if it ever exhausts its budget. Spawned does not log either itself.
pub(crate) fn watch(http: SupervisedChild<HttpServer>, supervisor: Supervisor) {
    tokio::spawn(async move {
        let mut seen = http.snapshot().generation;
        while http.wait_for_generation(seen).await.is_ok() {
            let snapshot = http.snapshot();
            warn!(
                child = %snapshot.name,
                generation = snapshot.generation,
                last_exit = ?snapshot.last_exit,
                last_error = ?snapshot.last_error,
                "Supervisor restarted the HTTP server"
            );
            seen = snapshot.generation;
        }
        supervisor.join().await;
        if let Some(failure) = supervisor.failure() {
            error!(
                %failure,
                "HTTP server supervisor gave up; the node runs on without its HTTP server"
            );
        }
    });
}

/// The environment variable that arms [`install_fault_injection`].
const FAULT_INJECTION_ENV: &str = "ETHLAMBDA_FAULT_INJECTION";

/// With `ETHLAMBDA_FAULT_INJECTION=1`, crash the current HTTP server on each
/// SIGUSR1, to exercise supervised recovery on a test node:
/// `kill -USR1 <pid>`. Off by default and out of every network-facing path.
pub(crate) fn install_fault_injection(http: SupervisedChild<HttpServer>) {
    if std::env::var(FAULT_INJECTION_ENV).as_deref() != Ok("1") {
        return;
    }
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut usr1 = match signal(SignalKind::user_defined1()) {
            Ok(usr1) => usr1,
            Err(err) => {
                warn!(%err, "Fault injection requested but SIGUSR1 cannot be handled");
                return;
            }
        };
        warn!("Fault injection armed: SIGUSR1 crashes the HTTP server");
        tokio::spawn(async move {
            while usr1.recv().await.is_some() {
                match http.current() {
                    Ok(server) => {
                        warn!(actor = %server.id(), "Fault injection: crashing the HTTP server");
                        let _ = server.send(InjectCrash);
                    }
                    Err(unavailable) => {
                        warn!(%unavailable, "Fault injection: no HTTP server to crash")
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use spawned_concurrency::supervision::ChildSpec;
    use spawned_concurrency::system::ActorSystem;

    use super::*;

    const RECOVERY: Duration = Duration::from_secs(15);

    /// A server that counts its runs; the first `failures` runs fail at once,
    /// the rest serve until cancelled.
    fn counting_server(failures: usize) -> (Serve, Arc<AtomicUsize>) {
        let runs = Arc::new(AtomicUsize::new(0));
        let counter = runs.clone();
        let serve: Serve = Arc::new(move |shutdown: CancellationToken| {
            let run = counter.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                if run < failures {
                    return Err(io::Error::other("address in use"));
                }
                shutdown.cancelled().await;
                Ok(())
            })
        });
        (serve, runs)
    }

    async fn supervised(
        system: &ActorSystem,
        serve: Serve,
    ) -> (SupervisedChild<HttpServer>, Supervisor) {
        let group = system.async_group("network", 1).unwrap();
        let mut tree = system.supervisor(supervisor_config()).unwrap();
        let http = tree
            .add(ChildSpec::new("http", &group, move |_| {
                let serve = serve.clone();
                async move { Ok::<_, std::convert::Infallible>(HttpServer::new(serve)) }
            }))
            .unwrap();
        let supervisor = tree.start().await.unwrap();
        (http, supervisor)
    }

    /// The fault-injection crash is a real handler panic: the supervisor
    /// builds a fresh actor, which serves again.
    #[tokio::test]
    async fn a_crashed_server_is_replaced_and_serves_again() {
        let system = ActorSystem::new().unwrap();
        let (serve, runs) = counting_server(0);
        let (http, _supervisor) = supervised(&system, serve).await;
        let first = http.wait_ready().await.unwrap();
        let generation = http.snapshot().generation;

        first.send(InjectCrash).unwrap();
        let second = tokio::time::timeout(RECOVERY, http.wait_for_generation(generation))
            .await
            .expect("the supervisor restarts the server")
            .unwrap();

        assert_ne!(first.id(), second.id());
        assert!(matches!(
            http.snapshot().last_exit,
            Some(spawned_concurrency::ExitReason::Panic(_))
        ));
        assert_eq!(runs.load(Ordering::SeqCst), 2);
        assert!(system.shutdown(RECOVERY).await.complete);
    }

    /// A server that fails to bind is retried, and one that keeps failing
    /// exhausts the budget and leaves the supervisor failed, not looping.
    #[tokio::test]
    async fn a_server_that_keeps_failing_exhausts_the_budget() {
        let system = ActorSystem::new().unwrap();
        let (serve, runs) = counting_server(usize::MAX);
        let (_http, supervisor) = supervised(&system, serve).await;

        tokio::time::timeout(Duration::from_secs(60), supervisor.join())
            .await
            .expect("the supervisor gives up within its budget");

        assert!(supervisor.failure().is_some());
        // The first run and one per restart the budget allows.
        assert_eq!(
            runs.load(Ordering::SeqCst),
            supervisor_config().max_restarts + 1
        );
        assert!(system.shutdown(RECOVERY).await.complete);
    }
}
