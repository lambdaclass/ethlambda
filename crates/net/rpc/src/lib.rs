use std::net::{IpAddr, SocketAddr};

use axum::{Extension, Router};
use ethlambda_blockchain::{EventBus, SyncStatusController};
use ethlambda_network_api::RpcToP2PRef;
use ethlambda_storage::Store;
use ethlambda_types::aggregator::AggregatorController;
use tokio_util::sync::CancellationToken;

pub(crate) const JSON_CONTENT_TYPE: &str = "application/json; charset=utf-8";
pub(crate) const SSZ_CONTENT_TYPE: &str = "application/octet-stream";

mod admin;
mod base;
mod beacon;
mod blocks;
mod events;
mod fork_choice;
mod genesis;
mod heap_profiling;
pub mod metrics;
mod node;
mod shared;
mod spec;
pub mod test_driver;

pub(crate) use base::json_response;

#[derive(Debug, Clone)]
pub struct RpcConfig {
    pub http_address: IpAddr,
    pub api_port: u16,
    pub metrics_port: u16,
    /// Full client version string, as printed by `ethlambda --version`.
    ///
    /// Served verbatim by `GET /lean/v0/node/identity`. It carries git and
    /// rustc build metadata that only the binary crate can produce (via its
    /// `build.rs`), so the binary supplies it here rather than the `net/rpc`
    /// crate building it itself.
    pub version: &'static str,
}

/// Start the RPC server in Hive test-driver mode.
///
/// Exposes only the `/lean/v0/test_driver/...` endpoints plus a `/lean/v0/health`
/// stub. The driver swaps its own `Store` on every `fork_choice/init`, so we
/// don't share state with the regular consensus path (which isn't running in
/// driver mode anyway — see `bin/ethlambda/src/main.rs`).
pub async fn start_test_driver_rpc_server(
    config: RpcConfig,
    driver: test_driver::DriverState,
    shutdown: CancellationToken,
) -> Result<(), std::io::Error> {
    let app = test_driver::build_router(driver);
    let addr = SocketAddr::new(config.http_address, config.api_port);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown.cancelled().await;
        })
        .await?;
    Ok(())
}

pub async fn start_rpc_server(
    config: RpcConfig,
    store: Store,
    aggregator: AggregatorController,
    sync_status: SyncStatusController,
    peer_id: String,
    events: EventBus,
    shutdown: CancellationToken,
) -> Result<(), std::io::Error> {
    let api_router = build_api_router(store, config.version, peer_id)
        .layer(Extension(aggregator))
        .layer(Extension(sync_status))
        .layer(Extension(events));
    start_http_servers(config, Some(api_router), shutdown).await
}

/// Bind and serve this process's HTTP surface, and return when it stops.
///
/// The metrics and debug routers are always served: they need no state, and a
/// process that records Prometheus series without serving them leaves the
/// question of whether it is healthy unanswerable. `api_router` is what the
/// caller has to supply, and is what differs between the two sub-commands.
///
/// `Some(router)` serves it alongside them: merged onto one listener when
/// `api_port == metrics_port`, otherwise on two independent servers, so
/// pointing both flags at one port is supported rather than a
/// misconfiguration. `None` serves only metrics and debug, on `metrics_port`;
/// `api_port` is then unused. That is `ethlambda beacon`, which has no lean
/// `Store`, `AggregatorController`, `SyncStatusController` or `EventBus` to
/// build the lean API from, and would be serving lean answers for a beacon
/// chain if it invented empty ones.
pub async fn start_http_servers(
    config: RpcConfig,
    api_router: Option<Router>,
    shutdown: CancellationToken,
) -> Result<(), std::io::Error> {
    let metrics_app = Router::new()
        .merge(metrics::start_prometheus_metrics_api())
        .merge(build_debug_router());

    let Some(api_router) = api_router else {
        return serve(
            config.http_address,
            config.metrics_port,
            metrics_app,
            shutdown,
        )
        .await;
    };

    if config.api_port == config.metrics_port {
        let app = Router::new().merge(api_router).merge(metrics_app);
        return serve(config.http_address, config.api_port, app, shutdown).await;
    }

    let metrics_shutdown = shutdown.clone();
    tokio::try_join!(
        serve(config.http_address, config.api_port, api_router, shutdown),
        serve(
            config.http_address,
            config.metrics_port,
            metrics_app,
            metrics_shutdown
        ),
    )?;
    Ok(())
}

/// Bind one listener and serve `app` on it until `shutdown` is cancelled.
async fn serve(
    address: IpAddr,
    port: u16,
    app: Router,
    shutdown: CancellationToken,
) -> Result<(), std::io::Error> {
    let addr = SocketAddr::new(address, port);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "HTTP server listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown.cancelled().await;
        })
        .await
}

/// Build the API router with the given store, client version, and peer ID.
///
/// `version` (`RpcConfig::version`) and `peer_id` (the node's libp2p peer ID)
/// are captured by the `/lean/v0/node/identity` route so it can report them.
/// The aggregator controller is threaded in separately via `Extension` by the
/// caller (see `start_rpc_server`) so existing store-backed handlers don't need
/// to know about it and admin handlers extract it independently.
fn build_api_router(store: Store, version: &'static str, peer_id: String) -> Router {
    Router::new()
        .merge(base::routes())
        .merge(blocks::routes())
        .merge(events::routes())
        .merge(fork_choice::routes())
        .merge(admin::routes())
        .merge(node::routes(version, peer_id))
        .merge(genesis::routes())
        .merge(spec::routes())
        .with_state(store)
}

/// Build the Beacon API router.
///
/// The mirror of [`build_api_router`], and deliberately not a superset of it:
/// the `/lean/v0` handlers read lean state variants and metadata keys a beacon
/// directory does not carry, so serving both off one store would answer lean
/// questions with beacon data, or panic trying.
///
/// The metrics and debug routers are **not** merged here, for the same reason
/// [`build_api_router`] does not merge them: [`start_http_servers`] serves
/// them itself, and merging a path twice makes axum panic at startup.
pub fn build_beacon_api_router(store: Store, version: &'static str, peer_id: String) -> Router {
    Router::new()
        .merge(beacon::routes(version, peer_id))
        .with_state(store)
}

/// What the Beacon API's validator endpoints reach beyond the store.
pub struct BeaconApiHandles {
    /// Through which the pool, aggregate and block endpoints gossip what a
    /// validator client hands them.
    pub p2p: RpcToP2PRef,
    /// The execution client block production builds payloads with; `None`
    /// makes it answer 503.
    pub engine: Option<ethlambda_engine::EngineClient>,
}

/// Start the HTTP servers for a beacon node.
///
/// The beacon counterpart to [`start_rpc_server`]. It takes no
/// `AggregatorController` and no `EventBus`: a follower has no aggregator duty
/// to toggle, and the chain-events stream is part of the lean surface. It does
/// take the [`BeaconApiHandles`] the validator endpoints need.
pub async fn start_beacon_rpc_server(
    config: RpcConfig,
    store: Store,
    sync_status: SyncStatusController,
    handles: BeaconApiHandles,
    peer_id: String,
    shutdown: CancellationToken,
) -> Result<(), std::io::Error> {
    let api_router = build_beacon_api_router(store, config.version, peer_id)
        .layer(Extension(sync_status))
        .layer(Extension(handles.p2p))
        .layer(Extension(beacon::validator::FeeRecipients::default()))
        .layer(Extension(handles.engine));
    start_http_servers(config, Some(api_router), shutdown).await
}

/// Build the debug router for profiling endpoints.
fn build_debug_router() -> Router {
    use axum::routing::get;
    Router::new()
        .route("/debug/pprof/allocs", get(heap_profiling::handle_get_heap))
        .route(
            "/debug/pprof/allocs/flamegraph",
            get(heap_profiling::handle_get_heap_flamegraph),
        )
}

#[cfg(test)]
pub(crate) mod test_utils {
    use std::sync::Arc;

    use axum::Router;
    use ethlambda_storage::{
        ForkCheckpoints, StorageBackend, Store, Table, backend::InMemoryBackend,
    };
    use ethlambda_types::{
        beacon::{
            config::Config,
            containers::{BeaconState, SignedBeaconBlock, phase0, shared::BeaconBlockHeader},
            preset,
        },
        block::{Block, BlockBody, BlockHeader},
        checkpoint::Checkpoint,
        primitives::{H256, HashTreeRoot as _},
        state::{JustificationValidators, JustifiedSlots, State, StateConfig},
    };
    use libssz::SszEncode;
    use libssz_types::SszVector;

    /// Build the API router the way tests do, with placeholder client version
    /// and peer ID. Tests that assert on those identity values (e.g. the
    /// `/lean/v0/node/identity` test) call `crate::build_api_router` directly.
    pub(crate) fn test_api_router(store: Store) -> Router {
        crate::build_api_router(store, "ethlambda/test", "test-peer".to_string())
    }

    /// Create a minimal test state for testing.
    pub(crate) fn create_test_state() -> State {
        let genesis_header = BlockHeader {
            slot: 0,
            proposer_index: 0,
            parent_root: H256::ZERO,
            state_root: H256::ZERO,
            body_root: BlockBody::default().hash_tree_root(),
        };

        let genesis_checkpoint = Checkpoint {
            root: H256::ZERO,
            slot: 0,
        };

        State {
            config: StateConfig { genesis_time: 1000 },
            slot: 0,
            latest_block_header: genesis_header,
            latest_justified: genesis_checkpoint,
            latest_finalized: genesis_checkpoint,
            historical_block_hashes: Default::default(),
            justified_slots: JustifiedSlots::new(),
            validators: Default::default(),
            justifications_roots: Default::default(),
            justifications_validators: JustificationValidators::new(),
        }
    }

    /// Build a block at the given slot with a trivial body.
    pub(crate) fn make_block(slot: u64, parent_root: H256) -> Block {
        Block {
            slot,
            proposer_index: 0,
            parent_root,
            state_root: H256::ZERO,
            body: BlockBody::default(),
        }
    }

    /// Insert a block's header (and body, if non-empty) into the backend.
    ///
    /// This bypasses `Store::insert_signed_block`, which requires XMSS
    /// signatures that are expensive to produce in tests.
    pub(crate) fn insert_block_raw(backend: &dyn StorageBackend, block: &Block) -> H256 {
        let header = block.header();
        let root = header.hash_tree_root();

        let mut batch = backend.begin_write().expect("write batch");
        batch
            .put_batch(Table::BlockHeaders, vec![(root.to_ssz(), header.to_ssz())])
            .expect("put header");
        if header.body_root != BlockBody::default().hash_tree_root() {
            batch
                .put_batch(
                    Table::BlockBodies,
                    vec![(root.to_ssz(), block.body.to_ssz())],
                )
                .expect("put body");
        }
        batch.commit().expect("commit");

        root
    }

    /// A two-block beacon store, built for reuse by every beacon HTTP test.
    pub(crate) struct BeaconFixture {
        pub(crate) store: Store,
        pub(crate) anchor_root: H256,
        // `anchor_slot`, `head_root` and `head_slot` are unread by this
        // task's own tests (which hardcode the fixture's slots since the
        // fixture itself is built from a fixed `ANCHOR_SLOT`), but are part
        // of what every later beacon-endpoint task reuses this fixture for.
        #[allow(dead_code)]
        pub(crate) anchor_slot: u64,
        #[allow(dead_code)]
        pub(crate) head_root: H256,
        #[allow(dead_code)]
        pub(crate) head_slot: u64,
    }

    /// A minimal phase0 state at `slot`, linked to `parent_root`.
    ///
    /// Mirrors `beacon_test_state`/`beacon_test_state_with_parent` in
    /// `ethlambda_storage::store`'s own tests: nothing here reads validators
    /// or history, so every fixed-length vector is zero-filled rather than
    /// populated with real content.
    fn phase0_beacon_state(slot: u64, parent_root: H256) -> phase0::BeaconState {
        phase0::BeaconState {
            genesis_time: 1_606_824_023,
            genesis_validators_root: H256::ZERO,
            slot,
            fork: Default::default(),
            latest_block_header: BeaconBlockHeader {
                slot,
                proposer_index: 0,
                parent_root,
                state_root: H256::ZERO,
                body_root: H256::ZERO,
            },
            block_roots: SszVector::try_from(vec![H256::ZERO; preset::SLOTS_PER_HISTORICAL_ROOT])
                .expect("exactly N elements by construction"),
            state_roots: SszVector::try_from(vec![H256::ZERO; preset::SLOTS_PER_HISTORICAL_ROOT])
                .expect("exactly N elements by construction"),
            historical_roots: Default::default(),
            eth1_data: Default::default(),
            eth1_data_votes: Default::default(),
            eth1_deposit_index: 0,
            validators: Default::default(),
            balances: Default::default(),
            randao_mixes: SszVector::try_from(vec![
                H256::ZERO;
                preset::EPOCHS_PER_HISTORICAL_VECTOR
            ])
            .expect("exactly N elements by construction"),
            slashings: SszVector::try_from(vec![0u64; preset::EPOCHS_PER_SLASHINGS_VECTOR])
                .expect("exactly N elements by construction"),
            previous_epoch_attestations: Default::default(),
            current_epoch_attestations: Default::default(),
            justification_bits: Default::default(),
            previous_justified_checkpoint: Default::default(),
            current_justified_checkpoint: Default::default(),
            finalized_checkpoint: Default::default(),
        }
    }

    /// A phase0 block at `slot`, with a trivial (default) body.
    fn phase0_beacon_block(slot: u64, parent_root: H256) -> SignedBeaconBlock {
        SignedBeaconBlock::Phase0(phase0::SignedBeaconBlock {
            message: phase0::BeaconBlock {
                slot,
                proposer_index: 0,
                parent_root,
                state_root: H256::ZERO,
                body: phase0::BeaconBlockBody::default(),
            },
            signature: Default::default(),
        })
    }

    /// Stands in for the P2P actor: records what the Beacon API would have
    /// gossiped instead of gossiping it.
    #[derive(Default)]
    pub(crate) struct RecordingNetwork {
        pub(crate) published: std::sync::Mutex<
            Vec<(
                u64,
                ethlambda_types::beacon::containers::electra::SingleAttestation,
            )>,
        >,
        pub(crate) aggregates:
            std::sync::Mutex<Vec<ethlambda_types::beacon::containers::SignedAggregateAndProof>>,
        pub(crate) operations:
            std::sync::Mutex<Vec<ethlambda_types::beacon::operation::BeaconOperation>>,
        pub(crate) subscriptions: std::sync::Mutex<Vec<(u64, u64)>>,
        pub(crate) blocks:
            std::sync::Mutex<Vec<ethlambda_types::beacon::containers::SignedBeaconBlock>>,
        pub(crate) sidecars:
            std::sync::Mutex<Vec<ethlambda_types::beacon::containers::fulu::DataColumnSidecar>>,
    }

    impl ethlambda_network_api::RpcToP2P for RecordingNetwork {
        fn publish_beacon_attestation(
            &self,
            subnet_id: u64,
            attestation: ethlambda_types::beacon::containers::electra::SingleAttestation,
        ) -> Result<(), spawned_concurrency::error::ActorError> {
            self.published
                .lock()
                .unwrap()
                .push((subnet_id, attestation));
            Ok(())
        }

        fn publish_beacon_aggregate(
            &self,
            aggregate: ethlambda_types::beacon::containers::SignedAggregateAndProof,
        ) -> Result<(), spawned_concurrency::error::ActorError> {
            self.aggregates.lock().unwrap().push(aggregate);
            Ok(())
        }

        fn publish_beacon_operation(
            &self,
            operation: ethlambda_types::beacon::operation::BeaconOperation,
        ) -> Result<(), spawned_concurrency::error::ActorError> {
            self.operations.lock().unwrap().push(operation);
            Ok(())
        }

        fn subscribe_attestation_subnets(
            &self,
            subnets: Vec<(u64, u64)>,
        ) -> Result<(), spawned_concurrency::error::ActorError> {
            self.subscriptions.lock().unwrap().extend(subnets);
            Ok(())
        }

        fn publish_beacon_block(
            &self,
            block: ethlambda_types::beacon::containers::SignedBeaconBlock,
            sidecars: Vec<ethlambda_types::beacon::containers::fulu::DataColumnSidecar>,
        ) -> Result<(), spawned_concurrency::error::ActorError> {
            self.blocks.lock().unwrap().push(block);
            self.sidecars.lock().unwrap().extend(sidecars);
            Ok(())
        }
    }

    /// A beacon store whose anchor, and so head, is `state`, under a block at
    /// the state's slot. Returns the store and that block's root.
    ///
    /// For endpoints that read the validator registry or committees, which the
    /// empty phase0 state in [`beacon_fixture`] cannot exercise. The block is a
    /// phase0 one whatever `state`'s fork: these endpoints read the state and
    /// the block's root and slot, never the block's body.
    pub(crate) fn beacon_store_at(state: BeaconState) -> (Store, H256) {
        let slot = state.slot();
        let block = phase0_beacon_block(slot, H256::ZERO);
        let root = block.message_hash_tree_root();
        let mut store = Store::init_beacon(
            Arc::new(InMemoryBackend::default()),
            1_606_824_023,
            Config::mainnet(),
            root,
            Checkpoint { root, slot },
            slot,
        );
        store
            .insert_signed_block(root, block)
            .expect("insert anchor block");
        store
            .insert_state(root, state)
            .expect("insert anchor state");
        store
            .update_checkpoints(ForkCheckpoints::head_only(root))
            .expect("make the anchor the head");
        (store, root)
    }

    /// Build a beacon store anchored at `anchor_slot`, with a real child block
    /// at `anchor_slot + 1` whose import moves the head for real.
    ///
    /// `Table::BlockRoots` is written only by `Store::update_checkpoints`
    /// (see `BlockId::resolve_beacon`'s doc), so a fixture that wants that
    /// table populated has to move the head through the real API rather than
    /// poke the backend directly. That is what distinguishes this from
    /// `beacon_test_state`/`beacon_test_block` in `ethlambda_storage::store`'s
    /// own tests, which this otherwise mirrors.
    pub(crate) fn beacon_fixture(anchor_slot: u64) -> BeaconFixture {
        let anchor_block = phase0_beacon_block(anchor_slot, H256::ZERO);
        let anchor_root = anchor_block.message_hash_tree_root();
        let anchor_state = phase0_beacon_state(anchor_slot, H256::ZERO);

        let mut store = Store::init_beacon(
            Arc::new(InMemoryBackend::default()),
            1_606_824_023,
            Config::mainnet(),
            anchor_root,
            Checkpoint {
                root: anchor_root,
                slot: anchor_slot,
            },
            anchor_slot,
        );
        store
            .insert_signed_block(anchor_root, anchor_block)
            .expect("insert anchor block");
        store
            .insert_state(anchor_root, BeaconState::Phase0(anchor_state))
            .expect("insert anchor state");

        let head_slot = anchor_slot + 1;
        let head_block = phase0_beacon_block(head_slot, anchor_root);
        let head_root = head_block.message_hash_tree_root();
        // `parent_root = anchor_root` so `insert_state`'s beacon arm diffs
        // against the anchor's own state rather than snapshotting again.
        let head_state = phase0_beacon_state(head_slot, anchor_root);

        store
            .insert_signed_block(head_root, head_block)
            .expect("insert head block");
        store
            .insert_state(head_root, BeaconState::Phase0(head_state))
            .expect("insert head state");

        store
            .update_checkpoints(ForkCheckpoints::head_only(head_root))
            .expect("move head to the child block");

        BeaconFixture {
            store,
            anchor_root,
            anchor_slot,
            head_root,
            head_slot,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request, http::StatusCode, http::header};
    use ethlambda_storage::{ForkCheckpoints, Store, backend::InMemoryBackend};
    use ethlambda_types::constants::DEFAULT_MILLISECONDS_PER_SLOT;
    use http_body_util::BodyExt;
    use serde_json::json;
    use std::sync::Arc;
    use tower::ServiceExt;

    use super::test_utils::create_test_state;

    #[tokio::test]
    async fn test_get_latest_justified_checkpoint() {
        let state = create_test_state();
        let backend = Arc::new(InMemoryBackend::new());
        let store = Store::from_anchor_state(backend, state, DEFAULT_MILLISECONDS_PER_SLOT);

        let app = test_utils::test_api_router(store.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/lean/v0/checkpoints/justified")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let checkpoint: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // The justified checkpoint should match the store's latest justified
        let expected = store
            .latest_justified()
            .expect("latest justified checkpoint exists");
        assert_eq!(
            checkpoint,
            json!({
                "slot": expected.slot,
                "root": format!("{}", expected.root)
            })
        );
    }

    #[tokio::test]
    async fn test_get_latest_finalized_state() {
        use ethlambda_types::primitives::H256;
        use libssz::SszEncode;
        let state = create_test_state();
        let backend = Arc::new(InMemoryBackend::new());
        let store = Store::from_anchor_state(backend, state, DEFAULT_MILLISECONDS_PER_SLOT);

        // Build expected SSZ with zeroed state_root (canonical post-state form)
        let finalized = store
            .latest_finalized()
            .expect("latest finalized checkpoint exists");
        let expected_state = store
            .get_state(&finalized.root)
            .expect("expected state")
            .unwrap();
        let mut expected_state = expected_state.expect_lean().clone();
        expected_state.latest_block_header.state_root = H256::ZERO;
        let expected_ssz = expected_state.to_ssz();

        let app = test_utils::test_api_router(store);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/lean/v0/states/finalized")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            SSZ_CONTENT_TYPE
        );

        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), expected_ssz.as_slice());
    }

    mod blocks {
        use super::*;
        use ethlambda_types::{
            primitives::{H256, HashTreeRoot as _},
            state::JustifiedSlots,
        };

        use crate::test_utils::{insert_block_raw, make_block};

        /// Build a store whose head state points back at `slot=1` via
        /// `historical_block_hashes`, with a real block stored at that slot.
        fn store_with_historical_block() -> (Store, H256) {
            let backend = Arc::new(InMemoryBackend::new());

            let target_block = make_block(1, H256::ZERO);
            let target_root = insert_block_raw(backend.as_ref(), &target_block);

            let mut anchor_state = create_test_state();
            anchor_state.slot = 2;
            anchor_state.latest_block_header.slot = 2;
            anchor_state.latest_block_header.parent_root = target_root;
            anchor_state.historical_block_hashes =
                vec![H256::ZERO, target_root].try_into().unwrap();
            anchor_state.justified_slots = JustifiedSlots::with_length(2).unwrap();

            let store =
                Store::from_anchor_state(backend, anchor_state, DEFAULT_MILLISECONDS_PER_SLOT);
            (store, target_root)
        }

        async fn send(app: axum::Router, uri: &str) -> axum::response::Response {
            app.oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap()
        }

        fn anchor_root_of(state: &ethlambda_types::state::State) -> H256 {
            let mut state = state.clone();
            state.latest_block_header.state_root = H256::ZERO;
            let state_root = state.hash_tree_root();
            state.latest_block_header.state_root = state_root;
            state.latest_block_header.hash_tree_root()
        }

        #[tokio::test]
        async fn get_block_by_root_returns_json() {
            let state = create_test_state();
            let anchor_root = anchor_root_of(&state);
            let backend = Arc::new(InMemoryBackend::new());
            let store = Store::from_anchor_state(backend, state, DEFAULT_MILLISECONDS_PER_SLOT);
            let app = test_utils::test_api_router(store);

            let response = send(app, &format!("/lean/v0/blocks/0x{anchor_root:x}")).await;

            assert_eq!(response.status(), StatusCode::OK);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

            assert_eq!(json["slot"], 0);
            assert_eq!(json["proposer_index"], 0);
            assert!(json["parent_root"].is_string());
            assert!(json["state_root"].is_string());
            assert!(json["body"]["attestations"].is_array());
        }

        #[tokio::test]
        async fn get_block_header_by_root_returns_json() {
            let state = create_test_state();
            let anchor_root = anchor_root_of(&state);
            let backend = Arc::new(InMemoryBackend::new());
            let store = Store::from_anchor_state(backend, state, DEFAULT_MILLISECONDS_PER_SLOT);
            let app = test_utils::test_api_router(store);

            let response = send(app, &format!("/lean/v0/blocks/0x{anchor_root:x}/header")).await;

            assert_eq!(response.status(), StatusCode::OK);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

            assert_eq!(json["slot"], 0);
            assert_eq!(json["proposer_index"], 0);
            assert!(json["body_root"].is_string());
        }

        #[tokio::test]
        async fn get_block_by_slot_returns_json() {
            let (store, _target_root) = store_with_historical_block();
            let app = test_utils::test_api_router(store);

            let response = send(app, "/lean/v0/blocks/1").await;

            assert_eq!(response.status(), StatusCode::OK);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

            assert_eq!(json["slot"], 1);
            assert!(json["body"]["attestations"].is_array());
        }

        #[tokio::test]
        async fn get_block_invalid_id_returns_400() {
            let state = create_test_state();
            let backend = Arc::new(InMemoryBackend::new());
            let store = Store::from_anchor_state(backend, state, DEFAULT_MILLISECONDS_PER_SLOT);
            let app = test_utils::test_api_router(store);

            let response = send(app, "/lean/v0/blocks/not-a-valid-id").await;

            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn get_block_missing_root_returns_404() {
            let state = create_test_state();
            let backend = Arc::new(InMemoryBackend::new());
            let store = Store::from_anchor_state(backend, state, DEFAULT_MILLISECONDS_PER_SLOT);
            let app = test_utils::test_api_router(store);

            let missing = format!("0x{}", "aa".repeat(32));
            let response = send(app, &format!("/lean/v0/blocks/{missing}")).await;

            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }

        #[tokio::test]
        async fn get_block_missing_slot_returns_404() {
            let (store, _) = store_with_historical_block();
            let app = test_utils::test_api_router(store);

            let response = send(app, "/lean/v0/blocks/999").await;

            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }

        #[tokio::test]
        async fn get_block_empty_slot_returns_404() {
            let (store, _) = store_with_historical_block();
            let app = test_utils::test_api_router(store);

            // Slot 0 in the test setup is H256::ZERO (empty).
            let response = send(app, "/lean/v0/blocks/0").await;

            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }
    }

    #[tokio::test]
    async fn test_get_latest_finalized_block() {
        use ethlambda_types::{
            beacon::containers::SignedBeaconBlock,
            block::{Block, BlockBody, MultiMessageAggregate, SignedBlock},
            checkpoint::Checkpoint,
            primitives::{H256, HashTreeRoot as _},
        };
        use libssz::SszEncode;

        let state = create_test_state();
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::from_anchor_state(backend, state, DEFAULT_MILLISECONDS_PER_SLOT);

        // Build a non-genesis signed block with empty body and empty proof blob.
        let block = Block {
            slot: 1,
            proposer_index: 0,
            parent_root: store
                .latest_finalized()
                .expect("latest finalized checkpoint exists")
                .root,
            state_root: H256::ZERO,
            body: BlockBody::default(),
        };
        let block_root = block.header().hash_tree_root();
        let signed_block = SignedBlock {
            message: block,
            proof: MultiMessageAggregate::default(),
        };

        // Persist the signed block and mark it as the latest finalized checkpoint.
        store
            .insert_signed_block(block_root, SignedBeaconBlock::Lean(signed_block.clone()))
            .expect("insert_signed_block should succeed");
        store
            .update_checkpoints(ForkCheckpoints::new(
                block_root,
                None,
                Some(Checkpoint {
                    root: block_root,
                    slot: 1,
                }),
            ))
            .expect("update_checkpoints should succeed");

        let expected_ssz = signed_block.to_ssz();

        let app = test_utils::test_api_router(store);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/lean/v0/blocks/finalized")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            SSZ_CONTENT_TYPE
        );

        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), expected_ssz.as_slice());
    }

    /// The same block, as JSON, when the caller asks for it by name.
    ///
    /// The default above stays SSZ and that is load-bearing:
    /// `bin/ethlambda/src/checkpoint_sync.rs` reads these bytes, and other
    /// clients' lean checkpoint sync may send no `Accept` at all. JSON here is
    /// opt-in, which is the opposite of the beacon surface's default.
    #[tokio::test]
    async fn the_lean_finalized_block_is_json_when_asked_for() {
        use ethlambda_types::{
            beacon::containers::SignedBeaconBlock,
            block::{Block, BlockBody, MultiMessageAggregate, SignedBlock},
            checkpoint::Checkpoint,
            primitives::{H256, HashTreeRoot as _},
        };

        let state = create_test_state();
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::from_anchor_state(backend, state, DEFAULT_MILLISECONDS_PER_SLOT);

        let block = Block {
            slot: 1,
            proposer_index: 0,
            parent_root: store
                .latest_finalized()
                .expect("latest finalized checkpoint exists")
                .root,
            state_root: H256::ZERO,
            body: BlockBody::default(),
        };
        let block_root = block.header().hash_tree_root();
        let signed_block = SignedBlock {
            message: block,
            proof: MultiMessageAggregate::default(),
        };
        store
            .insert_signed_block(block_root, SignedBeaconBlock::Lean(signed_block))
            .expect("insert_signed_block should succeed");
        store
            .update_checkpoints(ForkCheckpoints::new(
                block_root,
                None,
                Some(Checkpoint {
                    root: block_root,
                    slot: 1,
                }),
            ))
            .expect("update_checkpoints should succeed");

        let app = test_utils::test_api_router(store);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/lean/v0/blocks/finalized")
                    .header(header::ACCEPT, "application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            JSON_CONTENT_TYPE
        );

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // Lean encodes integers bare. This is not the beacon surface, whose
        // every integer is a quoted decimal string.
        assert_eq!(json["message"]["slot"], 1);
        assert_eq!(json["message"]["proposer_index"], 0);
    }

    #[tokio::test]
    async fn test_get_latest_finalized_block_serves_genesis_with_placeholder_proof() {
        use ethlambda_types::block::{MultiMessageAggregate, SignedBlock};
        use libssz::SszEncode;

        // Genesis-anchored store: `init_store` writes the header + state but no
        // `BlockProof` (proof) row. `get_signed_block` synthesizes an empty
        // proof so peers can still receive the genesis block on BlocksByRoot;
        // the HTTP endpoint stays consistent and returns 200 rather than 404.
        let state = create_test_state();
        let backend = Arc::new(InMemoryBackend::new());
        let store = Store::from_anchor_state(backend, state, DEFAULT_MILLISECONDS_PER_SLOT);

        // The body the endpoint serves must round-trip to a `SignedBlock`
        // matching the genesis header paired with the synthetic blank proof —
        // same shape `get_signed_block` builds in storage.
        let genesis_block = store
            .get_signed_block(
                &store
                    .latest_finalized()
                    .expect("latest finalized checkpoint exists")
                    .root,
            )
            .expect("genesis served via get_signed_block")
            .unwrap();
        let genesis_block = genesis_block.expect_lean();
        let expected = SignedBlock {
            message: genesis_block.message.clone(),
            proof: MultiMessageAggregate::default(),
        };
        let expected_ssz = expected.to_ssz();

        let app = test_utils::test_api_router(store);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/lean/v0/blocks/finalized")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            SSZ_CONTENT_TYPE
        );

        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), expected_ssz.as_slice());
    }
}
