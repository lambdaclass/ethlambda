//! Fetch real `(block, pre_state)` pairs from a running ethlambda node over RPC
//! and turn them into `StfInput`s to replay.

use ethlambda_prover_core::{StfInput, StfPublicValues};
use ethlambda_types::{block::Block, primitives::HashTreeRoot as _, state::State};
use eyre::{Context, bail};
use libssz::SszDecode as _;

/// A single transition ready to replay: the guest input plus the roots a
/// correct run must commit (computed here from the fetched block/state).
pub struct ReplayInput {
    pub id: String,
    pub input: StfInput,
    pub expected: StfPublicValues,
}

/// Fetch and assemble one transition, addressed by slot or `0x`-prefixed root.
pub async fn fetch_transition(
    client: &reqwest::Client,
    rpc_url: &str,
    block_id: &str,
) -> eyre::Result<ReplayInput> {
    let block = fetch_block(client, rpc_url, block_id)
        .await
        .wrap_err_with(|| format!("fetching block {block_id}"))?;

    // Pre-state = parent's post-state.
    let parent_hex = format!("0x{}", hex::encode(block.parent_root.0));
    let state = fetch_state(client, rpc_url, &parent_hex)
        .await
        .wrap_err_with(|| format!("fetching pre-state at parent {parent_hex}"))?;

    let expected = StfPublicValues {
        pre_state_root: state.hash_tree_root(),
        block_root: block.hash_tree_root(),
        // `state_transition` asserts the computed post-state equals this.
        post_state_root: block.state_root,
    };

    Ok(ReplayInput {
        id: block_id.to_string(),
        input: StfInput::new(state, block),
        expected,
    })
}

async fn fetch_block(client: &reqwest::Client, rpc_url: &str, id: &str) -> eyre::Result<Block> {
    let bytes = get_ssz(client, &format!("{rpc_url}/lean/v0/blocks/{id}/ssz")).await?;
    Block::from_ssz_bytes(&bytes).map_err(|e| eyre::eyre!("decoding block SSZ: {e:?}"))
}

async fn fetch_state(client: &reqwest::Client, rpc_url: &str, id: &str) -> eyre::Result<State> {
    let bytes = get_ssz(client, &format!("{rpc_url}/lean/v0/states/{id}")).await?;
    State::from_ssz_bytes(&bytes).map_err(|e| eyre::eyre!("decoding state SSZ: {e:?}"))
}

async fn get_ssz(client: &reqwest::Client, url: &str) -> eyre::Result<Vec<u8>> {
    let resp = client
        .get(url)
        .send()
        .await
        .wrap_err("HTTP request failed")?;
    if !resp.status().is_success() {
        bail!("GET {url} -> {}", resp.status());
    }
    Ok(resp
        .bytes()
        .await
        .wrap_err("reading response body")?
        .to_vec())
}
