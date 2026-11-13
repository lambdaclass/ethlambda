//! Helpers for writing files that hold secrets or decide what a validator
//! signs: the API token, imported keystores and their passwords, and the
//! validator definitions file, and the slashing-protection record.
//!
//! `std::fs::write` and `File::create` land at whatever mode the platform
//! default gives them, `0644` under a standard umask on unix, which makes
//! every one of those files readable by any other local account. Lighthouse's
//! convention here is `0600`; everything in this crate that writes such a
//! file must go through one of these two functions instead, to actually
//! follow that convention rather than only claim to.
//!
//! Both also flush what they wrote to the device before returning: an
//! imported keystore and its password are named by a definitions entry that
//! is made durable right after them (see [`write_private_durably`]), and that
//! entry must not survive a power loss the files it names did not.

use std::path::Path;

/// Write `contents` to `file` and flush them to the device.
fn write_durably(mut file: std::fs::File, contents: impl AsRef<[u8]>) -> std::io::Result<()> {
    use std::io::Write as _;
    file.write_all(contents.as_ref())?;
    file.sync_all()
}

/// Write `contents`, creating the file if it does not exist and truncating it
/// if it does, at mode `0600` on unix.
///
/// For a file this crate is the sole, trusted writer of and is willing to
/// overwrite outright: the API token. It is not named from
/// attacker-influenced input, so there is no symlink concern; see
/// [`write_private_no_symlink`] for the files that are, and
/// [`write_private_durably`] for the ones whose loss would change what a
/// validator signs.
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

/// Why [`write_private_durably`] failed, and whether the file had already
/// been replaced when it did.
#[derive(Debug)]
pub(crate) struct DurableWriteError {
    pub(crate) source: std::io::Error,
    /// The rename had happened: the new file is at its path, and only the
    /// directory flush that makes the rename survive a power loss failed.
    /// Until the next successful flush the file on disk may be either one.
    pub(crate) after_rename: bool,
}

impl std::fmt::Display for DurableWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.after_rename {
            write!(
                f,
                "written, but the directory could not be flushed, so the write may not survive \
                 a power loss: {}",
                self.source
            )
        } else {
            self.source.fmt(f)
        }
    }
}

impl std::error::Error for DurableWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Replace the file at `path` with `contents` so that a crash or power loss
/// leaves either the old file or the new one, never a mixture, and so that a
/// return of `Ok` means the new one is on disk. An error says whether the
/// file was already replaced when it failed (see [`DurableWriteError`]):
/// before the rename nothing at `path` changed; after it, only the flush that
/// makes the rename durable is missing. Unix only: elsewhere nothing is
/// touched and the write fails up front.
///
/// Written to a sibling `.tmp` created fresh at mode `0600`, flushed, renamed
/// over `path`, and then the directory is flushed so the rename itself
/// survives. For files whose loss or truncation would change what a validator
/// signs: the slashing-protection record and the validator definitions file.
///
/// The temporary is always a new file: whatever is at its path first, a
/// leftover of a write that crashed partway, or something planted there, is
/// removed, never reopened. A mode given at creation applies only at
/// creation, so reopening a leftover would carry its mode, whatever that was,
/// into the renamed record; and `O_EXCL` does not follow a symlink, so the
/// write cannot be redirected through one either. A write that fails before
/// the rename removes its temporary again, best effort.
#[cfg(unix)]
pub(crate) fn write_private_durably(
    path: &Path,
    contents: impl AsRef<[u8]>,
) -> Result<(), DurableWriteError> {
    use std::io::Write as _;
    let before = |source| DurableWriteError {
        source,
        after_rename: false,
    };
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    let temporary = path.with_file_name(name);

    match std::fs::remove_file(&temporary) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(before(err)),
    }
    let staged = (|| {
        let mut file = create_private(&temporary)?;
        file.write_all(contents.as_ref())?;
        file.sync_all()
    })()
    .and_then(|()| std::fs::rename(&temporary, path));
    if let Err(source) = staged {
        let _ = std::fs::remove_file(&temporary);
        return Err(before(source));
    }
    // `Path::new("record.json").parent()` is `Some("")`, not `None`, and
    // opening "" fails; the current directory is what it means.
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    sync_directory(directory).map_err(|source| DurableWriteError {
        source,
        after_rename: true,
    })
}

/// Off unix the directory flush is not implemented, so the write is refused
/// before anything is touched rather than answer `Ok` for a rename that may
/// not have reached the disk.
#[cfg(not(unix))]
pub(crate) fn write_private_durably(
    _path: &Path,
    _contents: impl AsRef<[u8]>,
) -> Result<(), DurableWriteError> {
    Err(DurableWriteError {
        source: std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "durable writes are only implemented on unix",
        ),
        after_rename: false,
    })
}

#[cfg(unix)]
fn create_private(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

/// Flush the directory, so a rename into it is itself durable.
///
/// `File::sync_all` is `fsync` everywhere but macOS, where it is
/// `F_FULLFSYNC`, the only request there that reaches the disk rather than
/// the drive's cache, and the one the file's own flush above already relies
/// on. Some macOS filesystems refuse that request for a directory, so there a
/// plain `fsync` is tried next: it is the best those offer, and the original
/// error is kept if even that fails. Only there: on Linux the two are the
/// same call, and a second `fsync` after a failed one can answer success
/// while the kernel has already dropped the writeback error with the data,
/// which would make a flush that did not happen look durable.
#[cfg(unix)]
fn sync_directory(directory: &Path) -> std::io::Result<()> {
    let directory = std::fs::File::open(directory)?;
    let result = directory.sync_all();
    #[cfg(target_os = "macos")]
    let result = result.or_else(|full_sync| {
        use std::os::fd::AsRawFd as _;
        // SAFETY: the descriptor is owned by `directory`, which outlives the call.
        if unsafe { libc::fsync(directory.as_raw_fd()) } == 0 {
            Ok(())
        } else {
            Err(full_sync)
        }
    });
    result
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
    fn write_private_durably_replaces_the_file_at_mode_0600() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("record");
        write_private_durably(&path, "first").expect("writes");
        write_private_durably(&path, "second").expect("replaces");

        assert_eq!(std::fs::read_to_string(&path).expect("reads"), "second");
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "got {mode:o}");
        assert!(
            !dir.path().join("record.tmp").exists(),
            "the temporary file is renamed away"
        );
    }

    #[test]
    fn write_private_durably_never_inherits_a_leftover_temporary_file_mode() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("record");
        // A write that crashed partway, under a permissive umask.
        let leftover = dir.path().join("record.tmp");
        std::fs::write(&leftover, "half").expect("writes leftover");
        std::fs::set_permissions(&leftover, std::fs::Permissions::from_mode(0o644)).expect("chmod");

        write_private_durably(&path, "whole").expect("writes");

        assert_eq!(std::fs::read_to_string(&path).expect("reads"), "whole");
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "got {mode:o}");
    }

    #[test]
    fn write_private_durably_does_not_write_through_a_symlink_at_the_temporary_path() {
        let dir = tempfile::tempdir().expect("temp dir");
        let target = dir.path().join("target");
        std::fs::write(&target, "untouched").expect("writes target");
        let path = dir.path().join("record");
        std::os::unix::fs::symlink(&target, dir.path().join("record.tmp")).expect("symlinks");

        write_private_durably(&path, "whole").expect("writes");

        assert_eq!(std::fs::read_to_string(&path).expect("reads"), "whole");
        assert_eq!(
            std::fs::read_to_string(&target).expect("reads"),
            "untouched",
            "the symlink target must be untouched"
        );
    }

    /// A write that fails before the rename takes its temporary with it, and
    /// says the file was not replaced.
    #[test]
    fn a_write_that_fails_before_the_rename_leaves_no_temporary() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("record");
        std::fs::create_dir(&path).expect("a directory in the file's place");

        let err = write_private_durably(&path, "x").expect_err("cannot rename over a directory");

        assert!(!err.after_rename, "{err}");
        assert!(!path.with_file_name("record.tmp").exists());
        assert!(path.is_dir(), "the directory is untouched");
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
