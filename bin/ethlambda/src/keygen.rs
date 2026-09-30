//! Validator key generation (`ethlambda keygen`).
//!
//! Writes the key set and manifest that `--hash-sig-keys-dir` reads, in the
//! layout `hash-sig-cli generate` produces, so `generate-genesis.sh` can call
//! this instead. Only the SSZ-and-postcard form is written: `hash-sig-cli` also
//! dumped each key as serde JSON, which its own help called legacy and nothing
//! reads.
//!
//! # Why the node generates its own keys
//!
//! An XMSS key file is only usable by a client built against the same scheme,
//! and the scheme lives in leanVM, which ethlambda pins. Nothing in the file
//! layout changes when the scheme does: leanVM's move from Poseidon over
//! KoalaBear to BLAKE2s over binary fields kept the public key at
//! [`PUBLIC_KEY_SIZE`] bytes and the secret key in postcard, so a key set from
//! the wrong revision passes every format check a genesis generator makes and
//! fails only once a signature is verified.
//!
//! Generating here removes the second pin that has to be kept in step: these
//! keys come from the same `ethlambda-crypto` types the node loads them with,
//! so the two cannot disagree. The manifest also records the leanVM revision
//! the binary was built against, which is the one field that cannot drift.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use ethlambda_crypto::signature::{ValidatorSecretKey, scheme};
use ethlambda_types::state::PUBLIC_KEY_SIZE;
use eyre::{Context as _, bail};
use tracing::info;

#[derive(Debug, clap::Args)]
pub(crate) struct KeygenOptions {
    /// Number of validators to generate a key pair for.
    ///
    /// Each validator gets two independent keys, an attester and a proposer, so
    /// that it can sign an attestation and a block in the same slot. The
    /// default generates one validator's pair, which is the shape for
    /// inspecting a key or replacing a single node's.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..))]
    num_validators: u32,

    /// Log2 of the slots each key can sign at, counted from slot 0.
    ///
    /// The default matches what the devnets generate. A key cannot sign past
    /// its range, so this is the network's lifetime: at the default cadence
    /// 2^18 slots is about 12 days.
    #[arg(long, default_value_t = 18, value_parser = clap::value_parser!(u32).range(1..=32))]
    log_num_active_epochs: u32,

    /// Directory to write the keys and manifest into. Created if absent.
    #[arg(long)]
    output_dir: PathBuf,

    /// Write `validator-keys-manifest.yaml` alongside the keys.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    create_manifest: bool,

    /// Name each validator by the first and last three bytes of its proposer
    /// public key rather than by index, for key sets split across hosts.
    #[arg(long)]
    distributed: bool,

    /// Overwrite key files already in `--output-dir`.
    ///
    /// Off by default: a key is one-time-use material, and silently replacing a
    /// set that validators are already signing with would make every one of
    /// them sign twice at the same slot under a key someone else now holds.
    #[arg(long)]
    force: bool,
}

/// One validator's generated key pair, as the manifest records it.
struct Validator {
    /// `validator_<i>`, or the pubkey-derived name under `--distributed`.
    name: String,
    proposer_pubkey: Vec<u8>,
    attester_pubkey: Vec<u8>,
}

pub(crate) fn run(options: KeygenOptions) -> eyre::Result<()> {
    let KeygenOptions {
        num_validators,
        log_num_active_epochs,
        output_dir,
        create_manifest,
        distributed,
        force,
    } = options;

    // Inclusive, so `2^n` slots is `0..=2^n - 1`. The exclusive reading is an
    // easy off-by-one to make here and gives every key one epoch too many.
    let last_slot = (1u64 << log_num_active_epochs) - 1;
    let last_slot = u32::try_from(last_slot)
        .wrap_err_with(|| format!("2^{log_num_active_epochs} slots exceeds the XMSS lifetime"))?;
    let slots = 0..=last_slot;

    fs::create_dir_all(&output_dir)
        .wrap_err_with(|| format!("failed to create {}", output_dir.display()))?;

    info!(
        num_validators,
        log_num_active_epochs,
        signable_slots = last_slot as u64 + 1,
        scheme = scheme::NAME,
        output_dir = %output_dir.display(),
        "Generating validator keys"
    );

    let mut validators = Vec::with_capacity(num_validators as usize);
    for index in 0..num_validators {
        // Two keys per validator, each with its own secret material: a shared
        // key would spend one slot's leaf on whichever duty signed first.
        let proposer = ValidatorSecretKey::generate(slots.clone())
            .wrap_err_with(|| format!("proposer key generation failed for validator {index}"))?;
        let attester = ValidatorSecretKey::generate(slots.clone())
            .wrap_err_with(|| format!("attester key generation failed for validator {index}"))?;

        let proposer_pubkey = proposer.public_key().to_bytes();
        let attester_pubkey = attester.public_key().to_bytes();
        let name = validator_name(index, distributed, &proposer_pubkey);

        write_key_pair(&output_dir, &name, "proposer", &proposer, force)?;
        write_key_pair(&output_dir, &name, "attester", &attester, force)?;

        info!(index, name, "Generated validator key pair");
        validators.push(Validator {
            name,
            proposer_pubkey,
            attester_pubkey,
        });
    }

    if create_manifest {
        let path = write_manifest(&output_dir, log_num_active_epochs, distributed, &validators)?;
        info!(manifest = %path.display(), "Wrote validator key manifest");
    }

    Ok(())
}

/// `validator_<i>`, or `validator-<first3>-<last3>` of the proposer public key.
///
/// The distributed form lets key directories from separate hosts be merged
/// without their indices colliding, at the cost of an ordering the genesis
/// generator has to take from the manifest rather than from the file names.
fn validator_name(index: u32, distributed: bool, proposer_pubkey: &[u8]) -> String {
    if !distributed {
        return format!("validator_{index}");
    }
    let (first, last) = proposer_pubkey.split_at(3);
    format!(
        "validator-{}-{}",
        hex::encode(first),
        hex::encode(&last[last.len() - 3..])
    )
}

/// Write one role's `_pk.ssz` and `_sk.ssz`.
///
/// The secret key is postcard rather than SSZ, which has no encoding for it;
/// the extension is kept so the genesis tooling needs no special case.
fn write_key_pair(
    output_dir: &Path,
    name: &str,
    role: &str,
    key: &ValidatorSecretKey,
    force: bool,
) -> eyre::Result<()> {
    let public = key.public_key().to_bytes();
    debug_assert_eq!(public.len(), PUBLIC_KEY_SIZE);
    let secret = key
        .to_bytes()
        .map_err(|err| eyre::eyre!("failed to encode the {role} secret key: {err}"))?;

    write_new(
        &output_dir.join(format!("{name}_{role}_key_pk.ssz")),
        &public,
        force,
    )?;
    write_new(
        &output_dir.join(format!("{name}_{role}_key_sk.ssz")),
        &secret,
        force,
    )
}

/// Write `path`, refusing to replace an existing file unless `force`.
fn write_new(path: &Path, bytes: &[u8], force: bool) -> eyre::Result<()> {
    if !force && path.exists() {
        bail!(
            "{} already exists; pass --force to replace the key set, \
             but only once no validator is still signing with it",
            path.display()
        );
    }
    fs::write(path, bytes).wrap_err_with(|| format!("failed to write {}", path.display()))
}

/// Write the manifest the genesis generator reads the public keys back from.
///
/// Hand-rolled rather than serialized from a struct, to hold the field order
/// and the blank lines `hash-sig-cli` produces: a diff between two key sets'
/// manifests is worth keeping readable.
fn write_manifest(
    output_dir: &Path,
    log_num_active_epochs: u32,
    distributed: bool,
    validators: &[Validator],
) -> eyre::Result<PathBuf> {
    let path = output_dir.join("validator-keys-manifest.yaml");
    let mut out = Vec::new();

    writeln!(out, "# Hash-Signature Validator Keys Manifest")?;
    writeln!(out, "# Generated by ethlambda keygen\n")?;
    writeln!(out, "key_scheme: {}", scheme::NAME)?;
    writeln!(out, "hash_function: {}", scheme::HASH_FUNCTION)?;
    writeln!(out, "encoding: {}", scheme::ENCODING)?;
    writeln!(out, "pubkey_bytes: {}", scheme::PUBLIC_KEY_BYTES)?;
    writeln!(out, "lifetime: {}", scheme::LIFETIME)?;
    // The scheme fields above are all derived from parameters that outlived the
    // last scheme change, so this is what actually identifies the key format.
    writeln!(out, "leanvm_rev: {}", crate::version::LEANVM_REV)?;
    writeln!(out, "log_num_active_epochs: {log_num_active_epochs}")?;
    writeln!(out, "num_active_epochs: {}", 1u64 << log_num_active_epochs)?;
    writeln!(out, "num_validators: {}\n", validators.len())?;
    writeln!(out, "validators:")?;

    for (index, validator) in validators.iter().enumerate() {
        // The distributed layout names validators by key rather than position,
        // so an index would be a second, conflicting identity.
        if !distributed {
            writeln!(out, "  - index: {index}")?;
        }
        let lead = if distributed { "  - " } else { "    " };
        writeln!(
            out,
            "{lead}proposer_key_pubkey_hex: 0x{}",
            hex::encode(&validator.proposer_pubkey)
        )?;
        writeln!(
            out,
            "    proposer_key_privkey_file: {}_proposer_key_sk.ssz",
            validator.name
        )?;
        writeln!(
            out,
            "    attester_key_pubkey_hex: 0x{}",
            hex::encode(&validator.attester_pubkey)
        )?;
        writeln!(
            out,
            "    attester_key_privkey_file: {}_attester_key_sk.ssz",
            validator.name
        )?;
        writeln!(out)?;
    }

    fs::write(&path, out).wrap_err_with(|| format!("failed to write {}", path.display()))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use ethlambda_crypto::signature::ValidatorPublicKey;

    use super::*;

    /// Read a public key back out of a generated `_pk.ssz`, which is what the
    /// node's own validator registry does with it.
    fn read_public_key(path: &Path) -> eyre::Result<ValidatorPublicKey> {
        let bytes =
            fs::read(path).wrap_err_with(|| format!("failed to read {}", path.display()))?;
        ValidatorPublicKey::from_bytes(&bytes)
            .map_err(|err| eyre::eyre!("{} is not a public key: {err}", path.display()))
    }

    fn options(dir: &Path, num_validators: u32) -> KeygenOptions {
        KeygenOptions {
            num_validators,
            // The smallest range that still exercises the subtree split, so the
            // tests stay fast: key generation cost grows with the range.
            log_num_active_epochs: 4,
            output_dir: dir.to_path_buf(),
            create_manifest: true,
            distributed: false,
            force: false,
        }
    }

    #[test]
    fn indexed_names_are_positional() {
        assert_eq!(validator_name(0, false, &[0xab; 32]), "validator_0");
        assert_eq!(validator_name(17, false, &[0xab; 32]), "validator_17");
    }

    /// The distributed name has to come from the key's own bytes, so two hosts
    /// generating independently cannot collide.
    #[test]
    fn distributed_names_come_from_the_proposer_key() {
        let mut pubkey = [0u8; PUBLIC_KEY_SIZE];
        pubkey[..3].copy_from_slice(&[0x01, 0x02, 0x03]);
        pubkey[PUBLIC_KEY_SIZE - 3..].copy_from_slice(&[0x0a, 0x0b, 0x0c]);

        let name = validator_name(0, true, &pubkey);
        assert_eq!(name, "validator-010203-0a0b0c");
        // The index is not in it, so the same key names the same validator
        // wherever it was generated.
        assert_eq!(name, validator_name(9, true, &pubkey));
    }

    /// The whole point of generating here: what comes out has to be what the
    /// node's key loader reads back, both keys and manifest.
    #[test]
    #[ignore = "slow: XMSS key generation"]
    fn generated_set_is_loadable_and_matches_its_manifest() {
        let dir = tempfile::tempdir().expect("tempdir");
        run(options(dir.path(), 2)).expect("keygen succeeds");

        let manifest = fs::read_to_string(dir.path().join("validator-keys-manifest.yaml"))
            .expect("manifest written");
        assert!(manifest.contains("num_validators: 2"), "{manifest}");
        assert!(manifest.contains("num_active_epochs: 16"), "{manifest}");
        assert!(
            manifest.contains(&format!("pubkey_bytes: {PUBLIC_KEY_SIZE}")),
            "{manifest}"
        );

        for index in 0..2 {
            for role in ["proposer", "attester"] {
                let name = format!("validator_{index}");
                let public = read_public_key(&dir.path().join(format!("{name}_{role}_key_pk.ssz")))
                    .expect("public key parses");
                let secret = fs::read(dir.path().join(format!("{name}_{role}_key_sk.ssz")))
                    .expect("secret key written");
                let secret = ValidatorSecretKey::from_bytes(&secret).expect("secret key parses");

                // The pair has to belong together, and the manifest has to
                // name the same public key the file holds.
                assert_eq!(secret.public_key().to_bytes(), public.to_bytes());
                assert_eq!(secret.signable_slots(), 0..=15);
                let hex = format!("0x{}", hex::encode(public.to_bytes()));
                assert!(
                    manifest.contains(&hex),
                    "{role} {index} missing from manifest"
                );
            }
        }
    }

    /// Two validators must not share key material, however close together they
    /// were generated.
    #[test]
    #[ignore = "slow: XMSS key generation"]
    fn every_generated_key_is_distinct() {
        let dir = tempfile::tempdir().expect("tempdir");
        run(options(dir.path(), 2)).expect("keygen succeeds");

        let mut seen = std::collections::HashSet::new();
        for index in 0..2 {
            for role in ["proposer", "attester"] {
                let path = dir
                    .path()
                    .join(format!("validator_{index}_{role}_key_pk.ssz"));
                let public = read_public_key(&path).expect("public key parses");
                assert!(
                    seen.insert(public.to_bytes()),
                    "validator_{index} {role} repeats another key"
                );
            }
        }
    }

    /// Replacing a live key set would make every validator in it sign twice at
    /// the same slot, so it takes an explicit `--force`.
    #[test]
    #[ignore = "slow: XMSS key generation"]
    fn an_existing_key_set_is_not_overwritten_by_default() {
        let dir = tempfile::tempdir().expect("tempdir");
        run(options(dir.path(), 1)).expect("first keygen succeeds");
        let before = fs::read(dir.path().join("validator_0_proposer_key_sk.ssz")).expect("written");

        let err = run(options(dir.path(), 1)).expect_err("a second run must refuse");
        assert!(err.to_string().contains("--force"), "{err}");

        let after = fs::read(dir.path().join("validator_0_proposer_key_sk.ssz")).expect("intact");
        assert_eq!(before, after, "the refused run must not have written");

        let mut forced = options(dir.path(), 1);
        forced.force = true;
        run(forced).expect("--force replaces the set");
        let replaced =
            fs::read(dir.path().join("validator_0_proposer_key_sk.ssz")).expect("written");
        assert_ne!(before, replaced, "--force must generate fresh material");
    }
}
