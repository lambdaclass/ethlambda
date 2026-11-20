//! PQ genesis key material (`ethlambda pq-keys`).
//!
//! A network on consensus-specs' `pq` fork registers, for every genesis
//! validator, a leanXMSS public key and the root of a VRF tree over all
//! `2^31` slots. The root costs the whole tree (minutes of every core per
//! validator, see `ethlambda_crypto::vrf`), so genesis tooling reads them
//! from precomputed files rather than deriving them at genesis time. This
//! writes those files for a mnemonic's validators, in the two formats
//! ethPandaOps' tooling reads:
//!
//! - `<name>.bin`, 64 bytes per validator index (the leanXMSS key, then the
//!   VRF root), which eth-beacon-genesis reads through `--xmss-pubkey-cache`
//!   or `--xmss-pubkey-url` (ethereum-package's `xmss_pubkey_url`), `<name>`
//!   being [`genesis_key_file_name`] of the mnemonic;
//! - `<name>.vrf`, [`STATE_RECORD_SIZE`] bytes per index (the root, then
//!   leaf 0's branch), which validator clients read through
//!   ethereum-package's `vrf_state_url` instead of hashing their trees.
//!
//! The keys come from each validator's EIP-2333 signing key at
//! `m/12381/3600/<index>/0/0`, as the generator and every PQ client derive
//! them (`ethlambda_crypto::pq_keys`), and the VRF tree is the one the
//! specification defines at this repository's pin. That is the reason to
//! generate them here: the files ethereum-package publishes follow whatever
//! rule its generator implements, and a genesis whose roots follow another
//! rule than the client's fails every proposal.
//!
//! Records are written one validator at a time, at their index's offset, so
//! an interrupted run resumes where it stopped: a validator whose records are
//! present and whose state folds to its root is skipped.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt as _;
use std::path::{Path, PathBuf};
use std::time::Instant;

use ethlambda_crypto::pq_keys::{
    bip39_seed, genesis_key_file_name, signing_key, vrf_seed, xmss_key,
};
use ethlambda_crypto::vrf::{STATE_RECORD_SIZE, VrfTree};
use eyre::{Context as _, OptionExt as _, bail};
use tracing::info;

/// The size of one `.bin` record: the leanXMSS key, then the VRF root.
const KEY_RECORD_SIZE: usize = 64;

#[derive(Debug, clap::Args)]
pub(crate) struct PqKeysOptions {
    /// The BIP-39 mnemonic the validators' keystores were derived from.
    #[arg(long, env = "ETHLAMBDA_PQ_KEYS_MNEMONIC", hide_env_values = true)]
    mnemonic: String,

    /// The first validator index to write.
    #[arg(long, default_value_t = 0)]
    start: u32,

    /// How many validators to write, from `--start`.
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
    count: u32,

    /// Directory to write `<name>.bin` and `<name>.vrf` into. Created if
    /// absent; existing records are kept and skipped.
    #[arg(long)]
    output_dir: PathBuf,
}

pub(crate) fn run(options: PqKeysOptions) -> eyre::Result<()> {
    let seed = bip39_seed(&options.mnemonic)
        .ok_or_eyre("the mnemonic must be ASCII (BIP-39's NFKD form is not applied)")?;
    let name = genesis_key_file_name(&seed);
    std::fs::create_dir_all(&options.output_dir)
        .wrap_err_with(|| format!("creating {}", options.output_dir.display()))?;
    let keys_path = options.output_dir.join(format!("{name}.bin"));
    let states_path = options.output_dir.join(format!("{name}.vrf"));
    let keys = open(&keys_path)?;
    let states = open(&states_path)?;
    info!(
        keys = %keys_path.display(),
        states = %states_path.display(),
        start = options.start,
        count = options.count,
        "Writing PQ genesis keys"
    );

    let started = Instant::now();
    let end = options
        .start
        .checked_add(options.count)
        .ok_or_eyre("--start plus --count overflows a validator index")?;
    for index in options.start..end {
        let sk = signing_key(&seed, index);
        let vrf_seed = vrf_seed(&sk);
        if let Some(root) = existing(&keys, &states, index, vrf_seed)? {
            info!(index, root = %hex::encode(root), "Already written");
            continue;
        }
        let key_started = Instant::now();
        let xmss_pubkey = xmss_key(&sk).public_key().to_bytes();
        let tree = VrfTree::build(vrf_seed);
        let root = tree.root();

        // The state first: a key record is what marks the index done.
        let state = tree.to_state_record();
        write_at(&states, &state, index, STATE_RECORD_SIZE, &states_path)?;
        let mut record = Vec::with_capacity(KEY_RECORD_SIZE);
        record.extend_from_slice(&xmss_pubkey);
        record.extend_from_slice(&root);
        write_at(&keys, &record, index, KEY_RECORD_SIZE, &keys_path)?;
        info!(
            index,
            xmss_pubkey = %hex::encode(xmss_pubkey),
            vrf_root = %hex::encode(root),
            elapsed_s = key_started.elapsed().as_secs(),
            "Wrote validator"
        );
    }
    info!(
        count = options.count,
        elapsed_s = started.elapsed().as_secs(),
        "PQ genesis keys written"
    );
    Ok(())
}

fn open(path: &Path) -> eyre::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .wrap_err_with(|| format!("opening {}", path.display()))
}

/// The root of `index`'s records when both are written and its state folds
/// this seed's leaf 0 to the root its key record names; `None` when it is to
/// be (re)written.
fn existing(
    keys: &File,
    states: &File,
    index: u32,
    vrf_seed: [u8; 32],
) -> eyre::Result<Option<[u8; 32]>> {
    let Some(key_record) = read_at(keys, index, KEY_RECORD_SIZE)? else {
        return Ok(None);
    };
    let Some(state) = read_at(states, index, STATE_RECORD_SIZE)? else {
        return Ok(None);
    };
    let Ok(tree) = VrfTree::from_state_record(vrf_seed, &state) else {
        return Ok(None);
    };
    let root = tree.root();
    if key_record[32..] != root {
        return Ok(None);
    }
    Ok(Some(root))
}

/// The record at `index`, or `None` when the file does not reach it or it
/// is all zeros (an index skipped by an earlier, later-starting run).
fn read_at(file: &File, index: u32, size: usize) -> eyre::Result<Option<Vec<u8>>> {
    let offset = u64::from(index) * size as u64;
    if file.metadata()?.len() < offset + size as u64 {
        return Ok(None);
    }
    let mut record = vec![0u8; size];
    file.read_exact_at(&mut record, offset)?;
    Ok((record.iter().any(|&byte| byte != 0)).then_some(record))
}

fn write_at(file: &File, record: &[u8], index: u32, size: usize, path: &Path) -> eyre::Result<()> {
    if record.len() != size {
        bail!(
            "a record of {} bytes where {size} are expected",
            record.len()
        );
    }
    file.write_all_at(record, u64::from(index) * size as u64)
        .and_then(|()| file.sync_data())
        .wrap_err_with(|| format!("writing validator {index} to {}", path.display()))
}
