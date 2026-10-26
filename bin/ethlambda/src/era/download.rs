//! Finding era files on disk and fetching the missing ones.
//!
//! Files come from `https://<network>.era.nimbus.team/`, an autoindex page
//! whose links are the file names. A file is named
//! `<config-name>-<NNNNN>-<8 hex>.era`; the trailing root is not predictable
//! from the era number, so the index is the only way to learn it.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use eyre::{WrapErr as _, ensure};
use reqwest::Client;
use tracing::info;

/// Log a download's progress this often, in bytes.
const PROGRESS_EVERY: u64 = 200 * 1024 * 1024;

pub(super) fn host(network: &str) -> String {
    format!("https://{network}.era.nimbus.team/")
}

/// Parse `<network>-<NNNNN>-<8 hex>.era` into its era number.
fn parse_era_name(name: &str, network: &str) -> Option<u64> {
    let rest = name.strip_prefix(network)?.strip_prefix('-')?;
    let rest = rest.strip_suffix(".era")?;
    let (era, root) = rest.split_once('-')?;
    let well_formed = era.len() == 5
        && era.bytes().all(|b| b.is_ascii_digit())
        && root.len() == 8
        && root.bytes().all(|b| b.is_ascii_hexdigit());
    well_formed.then(|| era.parse().expect("five digits"))
}

/// The era files an index page lists, by era number.
///
/// A name appears in the page twice (the link and its text), so the map also
/// dedups.
pub(super) fn parse_listing(page: &str, network: &str) -> BTreeMap<u64, String> {
    let prefix = format!("{network}-");
    let mut found = BTreeMap::new();
    for (start, _) in page.match_indices(&prefix) {
        // `<network>-NNNNN-xxxxxxxx.era`
        let len = prefix.len() + 5 + 1 + 8 + ".era".len();
        let Some(candidate) = page.get(start..start + len) else {
            continue;
        };
        if let Some(era) = parse_era_name(candidate, network) {
            found.insert(era, candidate.to_string());
        }
    }
    found
}

pub(super) async fn list_remote(
    client: &Client,
    network: &str,
) -> eyre::Result<BTreeMap<u64, String>> {
    let url = host(network);
    let page = client
        .get(&url)
        .send()
        .await
        .and_then(|response| response.error_for_status())
        .wrap_err_with(|| format!("listing {url}"))?
        .text()
        .await
        .wrap_err_with(|| format!("reading the listing at {url}"))?;
    let listing = parse_listing(&page, network);
    ensure!(!listing.is_empty(), "{url} lists no {network} era files");
    Ok(listing)
}

/// The file for `era` already in `dir`, if any.
pub(super) fn find_local(dir: &Path, network: &str, era: u64) -> eyre::Result<Option<PathBuf>> {
    let entries = std::fs::read_dir(dir).wrap_err_with(|| format!("reading {}", dir.display()))?;
    for entry in entries {
        let entry = entry?;
        if let Some(name) = entry.file_name().to_str()
            && parse_era_name(name, network) == Some(era)
        {
            return Ok(Some(entry.path()));
        }
    }
    Ok(None)
}

/// Download `file_name` into `dir`, through a `.part` file renamed on success
/// so an interrupted run never leaves something that looks complete.
pub(super) async fn fetch(
    client: &Client,
    network: &str,
    file_name: &str,
    dir: &Path,
) -> eyre::Result<PathBuf> {
    let url = format!("{}{file_name}", host(network));
    let destination = dir.join(file_name);
    let partial = dir.join(format!("{file_name}.part"));

    let mut response = client
        .get(&url)
        .send()
        .await
        .and_then(|response| response.error_for_status())
        .wrap_err_with(|| format!("downloading {url}"))?;
    let total = response.content_length();
    info!(%url, total_bytes = total, "Downloading era file");

    let mut file = std::fs::File::create(&partial)
        .wrap_err_with(|| format!("creating {}", partial.display()))?;
    let (mut written, mut next_report) = (0u64, PROGRESS_EVERY);
    while let Some(chunk) = response
        .chunk()
        .await
        .wrap_err_with(|| format!("downloading {url}"))?
    {
        file.write_all(&chunk)?;
        written += chunk.len() as u64;
        if written >= next_report {
            info!(file_name, downloaded_bytes = written, "Download progress");
            next_report += PROGRESS_EVERY;
        }
    }
    file.flush()?;
    if let Some(total) = total {
        ensure!(
            written == total,
            "{url} ended after {written} of {total} bytes"
        );
    }
    drop(file);
    std::fs::rename(&partial, &destination)
        .wrap_err_with(|| format!("renaming {} into place", partial.display()))?;
    Ok(destination)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &str = r#"<html><body><pre>
<a href="mainnet-00289-0a1b2c3d.era">mainnet-00289-0a1b2c3d.era</a>     20-Oct-2026 10:00  812345678
<a href="mainnet-00290-deadbeef.era">mainnet-00290-deadbeef.era</a>     20-Oct-2026 10:00  712345678
<a href="mainnet-00290-deadbeef.era.part">junk</a>
<a href="sepolia-00001-0a1b2c3d.era">sepolia-00001-0a1b2c3d.era</a>
</pre></body></html>"#;

    #[test]
    fn the_listing_yields_one_file_per_era_of_this_network() {
        let listing = parse_listing(PAGE, "mainnet");
        assert_eq!(listing.len(), 2);
        assert_eq!(listing[&290], "mainnet-00290-deadbeef.era");
        assert!(!listing.contains_key(&1));
    }

    #[test]
    fn local_files_are_matched_by_network_and_era() {
        let dir = tempfile::tempdir().unwrap();
        for name in [
            "mainnet-00290-deadbeef.era",
            "mainnet-00291-deadbeef.era.part",
            "hoodi-00290-deadbeef.era",
        ] {
            std::fs::write(dir.path().join(name), b"").unwrap();
        }
        let found = find_local(dir.path(), "mainnet", 290).unwrap().unwrap();
        assert!(found.ends_with("mainnet-00290-deadbeef.era"));
        assert!(find_local(dir.path(), "mainnet", 291).unwrap().is_none());
    }
}
