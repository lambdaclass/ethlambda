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
//!
//! Both also flush what they wrote to the device before returning. Each of
//! these files is one a later step relies on having reached disk: the
//! definitions file's `.tmp` sibling is renamed over the live file, and a
//! rename can survive a power loss that the data behind it did not, leaving
//! an empty definitions file, which parses as "no validators" rather than as
//! an error; an imported keystore and its password are named by a definitions
//! entry that is made durable right after them.

use std::path::Path;

/// Write `contents` to `file` and flush them to the device.
fn write_durably(mut file: std::fs::File, contents: impl AsRef<[u8]>) -> std::io::Result<()> {
    use std::io::Write as _;
    file.write_all(contents.as_ref())?;
    file.sync_all()
}

/// Flush a directory, which is what makes a `rename` into it durable: until
/// then a power loss can bring the old name's target back.
#[cfg(unix)]
pub(crate) fn sync_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

/// A directory cannot be opened as a file here; the rename is left to the
/// platform.
#[cfg(not(unix))]
pub(crate) fn sync_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

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
    use std::os::unix::fs::OpenOptionsExt as _;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    write_durably(file, contents)
}

#[cfg(not(unix))]
pub(crate) fn write_private(path: &Path, contents: impl AsRef<[u8]>) -> std::io::Result<()> {
    write_durably(std::fs::File::create(path)?, contents)
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
    use std::os::unix::fs::OpenOptionsExt as _;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    write_durably(file, contents)
}

#[cfg(not(unix))]
pub(crate) fn write_private_no_symlink(
    path: &Path,
    contents: impl AsRef<[u8]>,
) -> std::io::Result<()> {
    write_durably(std::fs::File::create(path)?, contents)
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

    /// `ValidatorDefinitions::save` calls this after every rename. It only
    /// logs a failure, so a platform that refused to flush a directory would
    /// show up as a warning on every keymanager write and nowhere else.
    #[test]
    fn sync_dir_flushes_a_directory() {
        let dir = tempfile::tempdir().expect("temp dir");
        write_private(&dir.path().join("secret"), "shh").expect("writes");
        sync_dir(dir.path()).expect("a directory can be flushed");
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
