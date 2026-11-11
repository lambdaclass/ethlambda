//! Helpers for writing files that hold secrets or decide what a validator
//! signs: the API token, imported keystores and their passwords, and the
//! validator definitions file.
//!
//! `std::fs::write` and `File::create` land at whatever mode the platform
//! default gives them, `0644` under a standard umask on unix, which makes
//! every one of those files readable by any other local account. Lighthouse's
//! convention here is `0600`; everything in this crate that writes such a
//! file must go through one of these two functions instead, to actually
//! follow that convention rather than only claim to.

use std::path::Path;

/// Write `contents`, creating the file if it does not exist and truncating it
/// if it does, at mode `0600` on unix.
///
/// For files this crate is always the sole, trusted writer of and is willing
/// to overwrite outright: the API token, and the validator definitions file's
/// `.tmp` sibling (`ValidatorDefinitions::save` renames it into place, which
/// preserves the mode set here). Neither is named from attacker-influenced
/// input, so there is no symlink concern for these; see
/// [`write_private_no_symlink`] for the ones that are.
#[cfg(unix)]
pub(crate) fn write_private(path: &Path, contents: impl AsRef<[u8]>) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents.as_ref())
}

#[cfg(not(unix))]
pub(crate) fn write_private(path: &Path, contents: impl AsRef<[u8]>) -> std::io::Result<()> {
    std::fs::write(path, contents)
}

/// Write `contents` at mode `0600`, refusing to follow an existing symlink at
/// `path`.
///
/// For the imported keystore and password files, whose names are derived
/// from the public key and are therefore predictable: an attacker able to
/// place a symlink at one of these paths ahead of a legitimate import must
/// not be able to redirect the write to an arbitrary target the operator can
/// write to. `O_NOFOLLOW` refuses to open the path at all when its final
/// component is a symlink, but still opens and truncates an existing regular
/// file, so re-importing the same key (the common case: rotating its
/// password, or simply retrying) overwrites its files exactly as before
/// rather than failing.
#[cfg(unix)]
pub(crate) fn write_private_no_symlink(
    path: &Path,
    contents: impl AsRef<[u8]>,
) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(contents.as_ref())
}

#[cfg(not(unix))]
pub(crate) fn write_private_no_symlink(
    path: &Path,
    contents: impl AsRef<[u8]>,
) -> std::io::Result<()> {
    std::fs::write(path, contents)
}

/// Replace the file at `path` with `contents` atomically and durably, at mode
/// `0600` on unix: written to a `.tmp` sibling, flushed to disk, renamed over
/// `path`, and the directory flushed so the rename itself survives a crash.
///
/// For a record that must be on disk before the action it guards, as an
/// EIP-8453 finality signing record must be before its signature: a reader
/// after a crash sees either the old record or the new one, never a torn or
/// lost write.
pub(crate) fn write_private_durable(
    path: &Path,
    contents: impl AsRef<[u8]>,
) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = std::path::PathBuf::from(tmp);
    {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(contents.as_ref())?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    #[cfg(unix)]
    {
        let dir = path
            .parent()
            .filter(|dir| !dir.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn write_private_creates_a_mode_0600_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("secret");
        write_private(&path, "shh").expect("writes");

        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "got {mode:o}");
        assert_eq!(std::fs::read_to_string(&path).expect("reads"), "shh");
    }

    #[test]
    fn write_private_no_symlink_creates_a_mode_0600_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("secret");
        write_private_no_symlink(&path, "shh").expect("writes");

        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "got {mode:o}");
    }

    #[test]
    fn write_private_no_symlink_overwrites_an_existing_regular_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("secret");
        write_private_no_symlink(&path, "first").expect("writes");
        write_private_no_symlink(&path, "second").expect("overwrites");

        assert_eq!(std::fs::read_to_string(&path).expect("reads"), "second");
    }

    #[test]
    fn write_private_no_symlink_refuses_to_follow_a_symlink() {
        let dir = tempfile::tempdir().expect("temp dir");
        let target = dir.path().join("target");
        std::fs::write(&target, "untouched").expect("writes target");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).expect("symlinks");

        let err = write_private_no_symlink(&link, "attacker-controlled")
            .expect_err("must refuse to follow the symlink");
        // `ErrorKind::FilesystemLoop` (the natural match for `O_NOFOLLOW`'s
        // `ELOOP`) is still unstable as of this toolchain, so match the raw
        // OS error instead.
        assert_eq!(err.raw_os_error(), Some(libc::ELOOP));
        assert_eq!(
            std::fs::read_to_string(&target).expect("reads"),
            "untouched",
            "the symlink target must be untouched"
        );
    }
}
