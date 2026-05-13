//! Live smoke test against a running EL (e.g. ethrex).
//!
//! Two modes:
//!
//!   # one-shot
//!   cargo run -p ethlambda-ethrex-client --example smoke -- \
//!       <auth-rpc-url> <jwt-secret-path>
//!
//!   # slot-cadence loop (4s/slot, matches ethlambda's tick interval)
//!   cargo run -p ethlambda-ethrex-client --example smoke -- \
//!       <auth-rpc-url> <jwt-secret-path> --loop <num-slots>
//!
//! The loop mode mirrors exactly what `BlockChainServer::on_tick` does at
//! interval 0 of every slot: build a `ForkChoiceState` and call
//! `engine_forkchoiceUpdatedV3`. Useful for end-to-end demos when a full
//! consensus run is overkill.

use std::time::Duration;

use ethlambda_ethrex_client::{
    ETHLAMBDA_ENGINE_CAPABILITIES, EngineClient, ForkChoiceState, JwtSecret,
};
use ethlambda_types::primitives::H256;

const SLOT_DURATION: Duration = Duration::from_secs(4);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let url = args.next().expect("usage: smoke <url> <jwt-path> [--loop <slots>]");
    let jwt_path = args.next().expect("usage: smoke <url> <jwt-path> [--loop <slots>]");
    let slot_count: Option<u32> = match (args.next(), args.next()) {
        (Some(ref flag), Some(n)) if flag == "--loop" => Some(n.parse()?),
        (None, None) => None,
        _ => {
            eprintln!("usage: smoke <url> <jwt-path> [--loop <slots>]");
            std::process::exit(2);
        }
    };

    let secret = JwtSecret::from_file(&jwt_path)?;
    let client = EngineClient::new(url, secret)?;

    println!("--- engine_exchangeCapabilities");
    let caps = client.exchange_capabilities(ETHLAMBDA_ENGINE_CAPABILITIES).await?;
    println!("EL advertises {} capabilities (showing first 6):", caps.len());
    for c in caps.iter().take(6) {
        println!("  {c}");
    }

    let Some(slots) = slot_count else {
        println!("\n--- engine_forkchoiceUpdatedV3 (one-shot, zeros)");
        let resp = client
            .forkchoice_updated_v3(zero_state(), None)
            .await?;
        println!("status    = {:?}", resp.payload_status.status);
        println!("payloadId = {:?}", resp.payload_id);
        return Ok(());
    };

    println!("\n--- engine_forkchoiceUpdatedV3 loop ({slots} slots @ 4s/slot)");
    for slot in 0..slots {
        let started = std::time::Instant::now();
        // Distinct head per slot so each call carries new data, exactly as
        // a real consensus run would (head_root changes on block import).
        let state = ForkChoiceState {
            head_block_hash: derive_root(b"head", slot),
            safe_block_hash: derive_root(b"safe", slot),
            finalized_block_hash: derive_root(b"final", slot),
        };
        let label = format!("slot={slot:>3}");
        match client.forkchoice_updated_v3(state, None).await {
            Ok(resp) => println!(
                "{label} engine_forkchoiceUpdatedV3 -> {:?} (latency {:?})",
                resp.payload_status.status,
                started.elapsed()
            ),
            Err(err) => println!("{label} engine_forkchoiceUpdatedV3 FAILED: {err}"),
        }
        if slot + 1 < slots {
            tokio::time::sleep(SLOT_DURATION.saturating_sub(started.elapsed())).await;
        }
    }

    Ok(())
}

fn zero_state() -> ForkChoiceState {
    ForkChoiceState {
        head_block_hash: H256::ZERO,
        safe_block_hash: H256::ZERO,
        finalized_block_hash: H256::ZERO,
    }
}

/// Hash-free pseudo-root derivation: just splat the slot number into the
/// 32-byte buffer prefixed by a domain tag. Real consensus uses
/// `hash_tree_root(Block)` — here we just want distinct values per slot.
fn derive_root(tag: &[u8], slot: u32) -> H256 {
    let mut out = [0u8; 32];
    let tag = &tag[..tag.len().min(8)];
    out[..tag.len()].copy_from_slice(tag);
    out[28..].copy_from_slice(&slot.to_be_bytes());
    H256(out)
}
