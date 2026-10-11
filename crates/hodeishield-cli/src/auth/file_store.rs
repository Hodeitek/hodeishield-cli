// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.

//! The opt-in plain-text token store: one JSON file per profile, readable only by its owner.
//!
//! This is the weaker of the two stores and is never chosen on its own: it is used only when
//! `HODEISHIELD_TOKEN_STORE=plaintext-file` or the global `token_store` setting says so. There is
//! no fallback in either direction (see `docs/decisions/0001-sign-in-without-a-keychain.md`).
//!
//! Files live in the platform's state directory (`$XDG_STATE_HOME/hodeishield/sessions/` on Linux, a
//! sibling of the application support folder on macOS), not in the configuration directory, so a copied or synced configuration never carries a token.
//! The file name is a hash of the profile name, which may contain `/` or `..`.
//!
//! On every read and write the CLI refuses, and never repairs, a file or directory that is a
//! symbolic link, that belongs to another user, or that is open to group or others. Windows has no
//! mode bits to check and is not supported yet.

use super::store::{Payload, StoredToken, TokenStore};
use crate::failure::{Failure, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Start of the message when the store refuses a file or directory it cannot trust. Commands that
/// need a credential turn it into "not authenticated" (exit code 3), like an unreachable keychain.
pub const TOKEN_FILE_REFUSED: &str = "the plain-text token store cannot be used";

/// What is written to the file: the profile it belongs to (checked on read) and the keychain
/// payload.
#[cfg_attr(not(unix), allow(dead_code))]
#[derive(Serialize, Deserialize)]
struct Record {
    profile: String,
    #[serde(flatten)]
    payload: Payload,
}

/// The sessions directory of this user, or why there is none.
pub fn sessions_dir() -> Result<PathBuf> {
    let dirs =
        directories::ProjectDirs::from("com", "Hodeitek", "HodeiShield").ok_or_else(|| {
            Failure::general("Cannot find a state directory for this user.")
                .hint("Use the system keychain or a tenant API key instead.")
        })?;
    if let Some(state) = dirs.state_dir() {
        return Ok(state.join("sessions"));
    }
    // macOS has no state directory, and its configuration and data directories are the same one.
    // A sibling of it, not a folder inside it, keeps the sessions out of the configuration
    // directory, which people copy, sync and back up.
    let data = dirs.data_local_dir();
    let name = data.file_name().map_or_else(
        || "com.Hodeitek.HodeiShield".into(),
        std::ffi::OsStr::to_os_string,
    );
    let mut sibling = name;
    sibling.push(".sessions");
    Ok(data.parent().unwrap_or(data).join(sibling))
}

/// The file name for a profile: the hex SHA-256 of its name, so no profile name can leave the
/// directory.
#[cfg_attr(not(unix), allow(dead_code))]
fn file_name(profile: &str) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write;
    let digest = Sha256::digest(profile.as_bytes());
    let mut name = digest.iter().fold(String::with_capacity(68), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    });
    name.push_str(".json");
    name
}

/// Plain-text files in a private directory.
#[cfg_attr(not(unix), allow(dead_code))]
#[derive(Debug, Clone)]
pub struct FileStore {
    dir: PathBuf,
}

impl FileStore {
    /// The store in the platform's state directory. Refused on Windows.
    pub fn platform() -> Result<Self> {
        if cfg!(windows) {
            return Err(unsupported());
        }
        Ok(Self::in_dir(sessions_dir()?))
    }

    pub(crate) fn in_dir(dir: PathBuf) -> Self {
        Self { dir }
    }

    #[cfg_attr(not(unix), allow(dead_code))]
    fn path_for(&self, profile: &str) -> PathBuf {
        self.dir.join(file_name(profile))
    }
}

fn unsupported() -> Failure {
    Failure::general(
        "the plain-text token store is not supported on Windows yet; signing in needs the \
         Windows Credential Manager",
    )
    .hint(
        "Leave token_store unset (or `keychain`), or use a tenant API key in HODEISHIELD_API_KEY.",
    )
}

#[cfg_attr(not(unix), allow(dead_code))]
fn refused(path: &Path, reason: &str, fix: Option<String>) -> Failure {
    let failure = Failure::general(format!("{TOKEN_FILE_REFUSED}: {} {reason}", path.display()));
    match fix {
        Some(fix) => failure.hint(format!(
            "It was left untouched. {fix} Or use a tenant API key in HODEISHIELD_API_KEY."
        )),
        None => failure.hint(
            "It was left untouched. Remove it yourself if you do not need it, or use a tenant API \
             key in HODEISHIELD_API_KEY.",
        ),
    }
}

#[cfg_attr(not(unix), allow(dead_code))]
fn io_failure(what: &str, path: &Path, error: &std::io::Error) -> Failure {
    Failure::general(format!("{what} {}: {error}", path.display()))
}

#[cfg(not(unix))]
impl TokenStore for FileStore {
    fn load(&self, _: &str) -> Result<Option<StoredToken>> {
        Err(unsupported())
    }
    fn save(&self, _: &str, _: &StoredToken) -> Result<()> {
        Err(unsupported())
    }
    fn delete(&self, _: &str) -> Result<bool> {
        Err(unsupported())
    }
    fn check_available(&self, _: &str) -> Result<()> {
        Err(unsupported())
    }
    fn location(&self, _: &str) -> Option<PathBuf> {
        None
    }
}

#[cfg(unix)]
impl TokenStore for FileStore {
    fn load(&self, profile: &str) -> Result<Option<StoredToken>> {
        unix::load(self, profile)
    }
    fn save(&self, profile: &str, token: &StoredToken) -> Result<()> {
        unix::save(self, profile, token)
    }
    fn delete(&self, profile: &str) -> Result<bool> {
        unix::delete(self, profile)
    }
    fn check_available(&self, profile: &str) -> Result<()> {
        unix::check_available(self, profile)
    }
    fn location(&self, profile: &str) -> Option<PathBuf> {
        Some(self.path_for(profile))
    }
}

#[cfg(unix)]
mod unix {
    use super::{FileStore, Record, io_failure, refused};
    use crate::auth::store::StoredToken;
    use crate::failure::{Failure, Result};
    use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, Stat};
    use rustix::io::Errno;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::fd::OwnedFd;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::path::Path;

    /// Biggest file read: a token payload is well under a kilobyte.
    const MAX_BYTES: u64 = 64 * 1024;

    /// A temporary file this old is a leftover of a crashed write, not one being written.
    const STALE_SECONDS: i64 = 60;

    /// The effective user id of this process.
    fn euid() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    fn io_error(errno: Errno) -> std::io::Error {
        std::io::Error::from(errno)
    }

    /// What is wrong with a file or directory, judged from its own `stat` (never a followed
    /// link): `None` when it can be trusted. The second string says how to fix a mode.
    pub(super) fn problem(stat: &Stat, want_dir: bool, euid: u32) -> Option<(String, String)> {
        let kind = FileType::from_raw_mode(stat.st_mode);
        let noun = if want_dir { "directory" } else { "file" };
        let fix_mode = if want_dir { "700" } else { "600" };
        if kind == FileType::Symlink {
            return Some((
                "is a symbolic link, which is never followed".into(),
                String::new(),
            ));
        }
        let right_type = if want_dir {
            kind == FileType::Directory
        } else {
            kind == FileType::RegularFile
        };
        if !right_type {
            return Some((format!("is not a regular {noun}"), String::new()));
        }
        if stat.st_uid != euid {
            return Some((
                format!("belongs to another user (uid {}), not to you", stat.st_uid),
                String::new(),
            ));
        }
        let mode = Mode::from_raw_mode(stat.st_mode).bits() & 0o777;
        if mode & 0o077 != 0 {
            return Some((
                format!(
                    "is accessible to other users (mode {mode:03o}); group and others must have \
                     no access"
                ),
                format!(
                    "If you own it and nobody else read it, `chmod {fix_mode}` fixes it; a token \
                     that may have been read should be revoked from the app."
                ),
            ));
        }
        None
    }

    fn check(path: &Path, stat: &Stat, want_dir: bool) -> Result<()> {
        match problem(stat, want_dir, euid()) {
            None => Ok(()),
            Some((reason, fix)) => Err(refused(path, &reason, Some(fix).filter(|f| !f.is_empty()))),
        }
    }

    /// The sessions directory as an open handle, checked with `fstat` on the handle itself. Every
    /// later operation is relative to it, so replacing the path afterwards cannot redirect them.
    /// `None` when absent and `create` is false; created with mode 0700 otherwise.
    pub(super) fn open_dir(store: &FileStore, create: bool) -> Result<Option<OwnedFd>> {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut created = false;
        loop {
            match rustix::fs::open(&store.dir, flags, Mode::empty()) {
                Ok(fd) => {
                    let stat = rustix::fs::fstat(&fd)
                        .map_err(|e| io_failure("Cannot look at", &store.dir, &io_error(e)))?;
                    check(&store.dir, &stat, true)?;
                    return Ok(Some(fd));
                }
                Err(Errno::NOENT) if create && !created => {
                    std::fs::DirBuilder::new()
                        .recursive(true)
                        .mode(0o700)
                        .create(&store.dir)
                        .map_err(|e| io_failure("Cannot create", &store.dir, &e))?;
                    created = true;
                }
                Err(Errno::NOENT) => return Ok(None),
                Err(e @ (Errno::LOOP | Errno::NOTDIR)) => {
                    // A link or something that is not a directory: say which.
                    let stat =
                        rustix::fs::statat(rustix::fs::CWD, &store.dir, AtFlags::SYMLINK_NOFOLLOW)
                            .map_err(|e| io_failure("Cannot look at", &store.dir, &io_error(e)))?;
                    check(&store.dir, &stat, true)?;
                    return Err(io_failure("Cannot open", &store.dir, &io_error(e)));
                }
                Err(e) => return Err(io_failure("Cannot open", &store.dir, &io_error(e))),
            }
        }
    }

    /// Looks at an entry of the directory without following a link. `None` when it is absent.
    fn look(dir: &OwnedFd, name: &str, path: &Path) -> Result<Option<Stat>> {
        match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => Ok(Some(stat)),
            Err(Errno::NOENT) => Ok(None),
            Err(e) => Err(io_failure("Cannot look at", path, &io_error(e))),
        }
    }

    /// Opens a file for reading and judges the opened handle, which must be the very file that
    /// was looked at (a swap in between is refused). A link, a FIFO or a device is never opened
    /// for long: `O_NOFOLLOW` refuses the first and `O_NONBLOCK` keeps the others from blocking.
    fn open_checked(dir: &OwnedFd, name: &str, path: &Path) -> Result<Option<File>> {
        let Some(seen) = look(dir, name, path)? else {
            return Ok(None);
        };
        check(path, &seen, false)?;
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let fd = match rustix::fs::openat(dir, name, flags, Mode::empty()) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(None),
            Err(Errno::LOOP) => {
                return Err(refused(
                    path,
                    "is a symbolic link, which is never followed",
                    None,
                ));
            }
            Err(e) => return Err(io_failure("Cannot read", path, &io_error(e))),
        };
        let opened =
            rustix::fs::fstat(&fd).map_err(|e| io_failure("Cannot read", path, &io_error(e)))?;
        if (opened.st_dev, opened.st_ino) != (seen.st_dev, seen.st_ino) {
            return Err(refused(path, "changed while it was being opened", None));
        }
        check(path, &opened, false)?;
        Ok(Some(File::from(fd)))
    }

    pub(super) fn load(store: &FileStore, profile: &str) -> Result<Option<StoredToken>> {
        let Some(dir) = open_dir(store, false)? else {
            return Ok(None);
        };
        let path = store.path_for(profile);
        let Some(file) = open_checked(&dir, &super::file_name(profile), &path)? else {
            return Ok(None);
        };
        let mut text = String::new();
        file.take(MAX_BYTES)
            .read_to_string(&mut text)
            .map_err(|e| io_failure("Cannot read", &path, &e))?;
        let corrupt = || {
            Failure::general(format!(
                "the sign-in stored in {} is unreadable",
                path.display()
            ))
            .hint(format!(
                "Remove {} and sign in again with `hodeishield login`.",
                path.display()
            ))
        };
        let record: Record = serde_json::from_str(&text).map_err(|_| corrupt())?;
        if record.profile != profile {
            return Err(corrupt());
        }
        Ok(Some(StoredToken::from_payload(record.payload)))
    }

    /// The first 16 hex digits of the profile's hash: what its temporary files start with.
    fn prefix(profile: &str) -> String {
        super::file_name(profile)[..16].to_owned()
    }

    fn temp_name(profile: &str) -> Result<String> {
        let mut random = [0u8; 8];
        getrandom::fill(&mut random)
            .map_err(|e| Failure::general(format!("cannot get random bytes: {e}")))?;
        let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
        Ok(format!(".{}.{suffix}.tmp", prefix(profile)))
    }

    /// Whether `name` is `.<prefix>.<16 hex digits>.tmp`, exactly what [`temp_name`] makes.
    fn is_temp_of(name: &str, profile: &str) -> bool {
        name.strip_prefix('.')
            .and_then(|rest| rest.strip_prefix(prefix(profile).as_str()))
            .and_then(|rest| rest.strip_prefix('.'))
            .and_then(|rest| rest.strip_suffix(".tmp"))
            .is_some_and(|random| {
                random.len() == 16
                    && random
                        .bytes()
                        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            })
    }

    /// Removes the profile's temporary files left by a write that crashed between creating the
    /// file and renaming it: they hold live tokens. Only regular files of this user that are old
    /// enough not to be a write in progress by another process. Best effort.
    fn remove_leftovers(dir: &OwnedFd, profile: &str) {
        let Ok(entries) = Dir::read_from(dir) else {
            return;
        };
        let now = i64::try_from(crate::auth::now()).unwrap_or(i64::MAX);
        let names: Vec<String> = entries
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| entry.file_name().to_str().ok().map(str::to_owned))
            .filter(|name| is_temp_of(name, profile))
            .collect();
        for name in names {
            let Ok(stat) = rustix::fs::statat(dir, name.as_str(), AtFlags::SYMLINK_NOFOLLOW) else {
                continue;
            };
            if FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
                && stat.st_uid == euid()
                && now.saturating_sub(stat.st_mtime) >= STALE_SECONDS
            {
                let _ = rustix::fs::unlinkat(dir, name.as_str(), AtFlags::empty());
            }
        }
    }

    /// Removes the temporary file unless it was renamed into place.
    struct Temp<'a> {
        dir: &'a OwnedFd,
        name: String,
        armed: bool,
    }

    impl Drop for Temp<'_> {
        fn drop(&mut self) {
            if self.armed {
                let _ = rustix::fs::unlinkat(self.dir, self.name.as_str(), AtFlags::empty());
            }
        }
    }

    fn create_new(dir: &OwnedFd, name: &str, path: &Path) -> Result<File> {
        let flags =
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        rustix::fs::openat(dir, name, flags, Mode::RUSR | Mode::WUSR)
            .map(File::from)
            .map_err(|e| io_failure("Cannot create", path, &io_error(e)))
    }

    /// Writes `bytes` to a new 0600 file in the directory and renames it over `name`.
    pub(super) fn write_atomically(
        store: &FileStore,
        dir: &OwnedFd,
        profile: &str,
        bytes: &[u8],
    ) -> Result<()> {
        let temp = temp_name(profile)?;
        let temp_path = store.dir.join(&temp);
        let mut file = create_new(dir, &temp, &temp_path)?;
        let mut guard = Temp {
            dir,
            name: temp.clone(),
            armed: true,
        };
        // The umask can only remove bits from 0600; say 0600 whatever it was.
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .and_then(|()| file.write_all(bytes))
            .and_then(|()| file.sync_all())
            .map_err(|e| io_failure("Cannot write", &temp_path, &e))?;
        drop(file);
        let target = store.path_for(profile);
        rustix::fs::renameat(dir, temp.as_str(), dir, super::file_name(profile).as_str())
            .map_err(|e| io_failure("Cannot replace", &target, &io_error(e)))?;
        guard.armed = false;
        // Makes the rename durable. Best effort: not every file system allows it.
        let _ = rustix::fs::fsync(dir);
        Ok(())
    }

    pub(super) fn save(store: &FileStore, profile: &str, token: &StoredToken) -> Result<()> {
        let dir = open_dir(store, true)?
            .ok_or_else(|| Failure::general(format!("Cannot create {}.", store.dir.display())))?;
        remove_leftovers(&dir, profile);
        let path = store.path_for(profile);
        // An existing file is judged before it is replaced, even though it will not be read.
        if let Some(stat) = look(&dir, &super::file_name(profile), &path)? {
            check(&path, &stat, false)?;
        }
        let record = Record {
            profile: profile.to_owned(),
            payload: token.to_payload(),
        };
        let mut text = serde_json::to_string(&record)
            .map_err(|e| Failure::general(format!("cannot encode the sign-in: {e}")))?;
        text.push('\n');
        write_atomically(store, &dir, profile, text.as_bytes())
    }

    pub(super) fn delete(store: &FileStore, profile: &str) -> Result<bool> {
        let Some(dir) = open_dir(store, false)? else {
            return Ok(false);
        };
        remove_leftovers(&dir, profile);
        let name = super::file_name(profile);
        let path = store.path_for(profile);
        let Some(stat) = look(&dir, &name, &path)? else {
            return Ok(false);
        };
        check(&path, &stat, false)?;
        match rustix::fs::unlinkat(&dir, name.as_str(), AtFlags::empty()) {
            Ok(()) => {
                let _ = rustix::fs::fsync(&dir);
                Ok(true)
            }
            Err(Errno::NOENT) => Ok(false),
            Err(e) => Err(io_failure("Cannot remove", &path, &io_error(e))),
        }
    }

    /// Proves the store can be used: the directory exists with the right owner and mode (it is
    /// created if absent), the profile's file, if any, is trustworthy, and an empty file can be
    /// created and removed there. No token is written.
    pub(super) fn check_available(store: &FileStore, profile: &str) -> Result<()> {
        let dir = open_dir(store, true)?
            .ok_or_else(|| Failure::general(format!("Cannot create {}.", store.dir.display())))?;
        let path = store.path_for(profile);
        if let Some(stat) = look(&dir, &super::file_name(profile), &path)? {
            check(&path, &stat, false)?;
        }
        let probe = temp_name(profile)?;
        create_new(&dir, &probe, &store.dir.join(&probe)).map_err(|e| {
            Failure::general(format!(
                "{}: cannot write in {}: {}",
                super::TOKEN_FILE_REFUSED,
                store.dir.display(),
                e.message
            ))
            .hint("Use the system keychain or a tenant API key in HODEISHIELD_API_KEY.")
        })?;
        let _ = rustix::fs::unlinkat(&dir, probe.as_str(), AtFlags::empty());
        if let Some(fs) = super::network_file_system(&store.dir) {
            eprintln!(
                "Warning: {} is on {fs}. A file there can be read by the server's administrator \
                 and by root on other machines that mount it; use a local directory \
                 (XDG_STATE_HOME) if that matters.",
                store.dir.display()
            );
        }
        Ok(())
    }
}

/// The name of the network file system `path` is on, when it can be told cheaply and reliably.
/// Only Linux's `statfs` magic numbers are used; elsewhere nothing is detected.
#[cfg(all(unix, target_os = "linux"))]
fn network_file_system(path: &Path) -> Option<&'static str> {
    let stat = rustix::fs::statfs(path).ok()?;
    network_file_system_for(stat.f_type as u64 & 0xFFFF_FFFF)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn network_file_system(_: &Path) -> Option<&'static str> {
    None
}

/// Linux `statfs` `f_type` values of file systems served by another machine.
#[cfg(any(test, all(unix, target_os = "linux")))]
fn network_file_system_for(f_type: u64) -> Option<&'static str> {
    match f_type {
        0x6969 => Some("NFS"),
        0xFF53_4D42 | 0xFE53_4D42 => Some("SMB/CIFS"),
        _ => None,
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use secrecy::{ExposeSecret, SecretString};
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    fn token() -> StoredToken {
        StoredToken {
            access_token: SecretString::from("at_secret"),
            refresh_token: Some(SecretString::from("rt_secret")),
            expires_at: Some(1_000),
            scope: Some("read".to_owned()),
            issuer: "https://app.example.test".to_owned(),
            api_url: "https://api.example.test".to_owned(),
            client_id: "cli".to_owned(),
        }
    }

    /// A store in `<tmp>/sessions`, which does not exist yet.
    fn store() -> (tempfile::TempDir, FileStore) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = FileStore::in_dir(tmp.path().join("sessions"));
        (tmp, store)
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).expect("meta").mode() & 0o777
    }

    fn refused_with(result: Result<impl std::fmt::Debug>, needle: &str) {
        let err = result.expect_err("refused");
        assert!(
            err.message.starts_with(TOKEN_FILE_REFUSED) && err.message.contains(needle),
            "{}",
            err.message
        );
        assert!(err.hint.is_some());
    }

    fn saved() -> (tempfile::TempDir, FileStore) {
        let (tmp, store) = store();
        store.save("p", &token()).expect("save");
        (tmp, store)
    }

    #[test]
    fn a_session_round_trips_with_private_modes() {
        let (_tmp, store) = saved();
        let back = store.load("p").expect("load").expect("stored");
        assert_eq!(back.access_token.expose_secret(), "at_secret");
        assert_eq!(back.refresh_token.expect("rt").expose_secret(), "rt_secret");
        assert_eq!(mode(&store.dir), 0o700);
        assert_eq!(mode(&store.path_for("p")), 0o600);
        assert!(store.load("other").expect("load").is_none());
    }

    #[test]
    fn an_atomic_write_leaves_no_temporary_file_and_replaces_the_old_one() {
        let (_tmp, store) = saved();
        let newer = StoredToken {
            access_token: SecretString::from("at_newer"),
            ..token()
        };
        store.save("p", &newer).expect("save again");
        let names: Vec<_> = std::fs::read_dir(&store.dir)
            .expect("dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(names, [std::ffi::OsString::from(file_name("p"))]);
        assert_eq!(mode(&store.path_for("p")), 0o600);
        let back = store.load("p").expect("load").expect("stored");
        assert_eq!(back.access_token.expose_secret(), "at_newer");
    }

    #[test]
    fn a_refused_target_leaves_no_temporary_file() {
        let (_tmp, store) = saved();
        std::fs::create_dir(store.path_for("q")).expect("blocker");
        refused_with(store.save("q", &token()), "not a regular file");
        let leftovers: Vec<_> = std::fs::read_dir(&store.dir)
            .expect("dir")
            .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
        assert!(store.load("p").expect("load").is_some());
    }

    #[test]
    fn a_symlinked_file_is_refused_on_every_operation() {
        let (tmp, store) = saved();
        let real = tmp.path().join("real.json");
        std::fs::copy(store.path_for("p"), &real).expect("copy");
        std::fs::remove_file(store.path_for("p")).expect("rm");
        symlink(&real, store.path_for("p")).expect("link");
        refused_with(store.load("p"), "symbolic link");
        refused_with(store.save("p", &token()), "symbolic link");
        refused_with(store.delete("p"), "symbolic link");
        refused_with(store.check_available("p"), "symbolic link");
        // Left as it was.
        assert!(
            std::fs::symlink_metadata(store.path_for("p"))
                .expect("meta")
                .is_symlink()
        );
        assert!(real.exists());
    }

    #[test]
    fn a_symlinked_directory_is_refused() {
        let (tmp, store) = store();
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).expect("dir");
        std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o700))
            .expect("chmod");
        symlink(&elsewhere, &store.dir).expect("link");
        refused_with(store.load("p"), "symbolic link");
        refused_with(store.save("p", &token()), "symbolic link");
        refused_with(store.delete("p"), "symbolic link");
        refused_with(store.check_available("p"), "symbolic link");
        assert_eq!(std::fs::read_dir(&elsewhere).expect("dir").count(), 0);
    }

    #[test]
    fn a_file_open_to_group_or_others_is_refused() {
        for bits in [0o644, 0o640, 0o604, 0o660] {
            let (_tmp, store) = saved();
            let path = store.path_for("p");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(bits)).expect("chmod");
            refused_with(store.load("p"), "accessible to other users");
            refused_with(store.save("p", &token()), "accessible to other users");
            refused_with(store.delete("p"), "accessible to other users");
            refused_with(store.check_available("p"), "accessible to other users");
            // Never repaired.
            assert_eq!(mode(&path), bits);
        }
    }

    #[test]
    fn a_directory_open_to_group_or_others_is_refused() {
        for bits in [0o755, 0o750, 0o705] {
            let (_tmp, store) = saved();
            std::fs::set_permissions(&store.dir, std::fs::Permissions::from_mode(bits))
                .expect("chmod");
            refused_with(store.load("p"), "no access");
            refused_with(store.save("p", &token()), "no access");
            refused_with(store.delete("p"), "no access");
            refused_with(store.check_available("p"), "no access");
            assert_eq!(mode(&store.dir), bits);
            std::fs::set_permissions(&store.dir, std::fs::Permissions::from_mode(0o700))
                .expect("chmod back");
        }
    }

    #[test]
    fn the_owner_is_compared_with_the_effective_user() {
        // Another user's files cannot be made in a test, so the judgement is exercised with the
        // effective uid replaced: the same file is then someone else's.
        let (_tmp, store) = saved();
        let stat = rustix::fs::lstat(store.path_for("p")).expect("stat");
        let me = stat.st_uid;
        assert!(unix::problem(&stat, false, me).is_none());
        let (reason, _) = unix::problem(&stat, false, me.wrapping_add(1)).expect("another owner");
        assert!(reason.contains("belongs to another user"), "{reason}");
        let dir_stat = rustix::fs::lstat(&store.dir).expect("stat");
        assert!(unix::problem(&dir_stat, true, me.wrapping_add(1)).is_some());
        assert_eq!(rustix::process::geteuid().as_raw(), me);
    }

    fn tmp_files(store: &FileStore) -> Vec<String> {
        std::fs::read_dir(&store.dir)
            .expect("dir")
            .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
            .filter(|n| n.ends_with(".tmp"))
            .collect()
    }

    #[test]
    fn a_failed_rename_removes_the_temporary_file() {
        let (_tmp, store) = saved();
        // A non-empty directory where the file belongs makes the rename fail after the temporary
        // file was written.
        let target = store.path_for("q");
        std::fs::create_dir(&target).expect("blocker");
        std::fs::write(target.join("x"), "x").expect("fill");
        let dir = unix::open_dir(&store, false)
            .expect("open")
            .expect("exists");
        let err = unix::write_atomically(&store, &dir, "q", b"secret").expect_err("rename fails");
        assert!(err.message.starts_with("Cannot replace"), "{}", err.message);
        assert!(tmp_files(&store).is_empty(), "{:?}", tmp_files(&store));
    }

    #[test]
    fn leftover_temporary_files_of_the_profile_are_removed_when_stale() {
        for deleting in [false, true] {
            let (_tmp, store) = saved();
            let prefix = &file_name("p")[..16];
            let stale = store.dir.join(format!(".{prefix}.0123456789abcdef.tmp"));
            let fresh = store.dir.join(format!(".{prefix}.fedcba9876543210.tmp"));
            let other = store
                .dir
                .join(format!(".{}.0123456789abcdef.tmp", &file_name("q")[..16]));
            let odd = store.dir.join(format!(".{prefix}.not-hex.tmp"));
            for path in [&stale, &fresh, &other, &odd] {
                std::fs::write(path, "token").expect("write");
            }
            let old = std::time::SystemTime::now() - std::time::Duration::from_secs(600);
            for path in [&stale, &other] {
                std::fs::File::options()
                    .write(true)
                    .open(path)
                    .expect("open")
                    .set_modified(old)
                    .expect("age it");
            }
            if deleting {
                store.delete("p").expect("delete");
            } else {
                store.save("p", &token()).expect("save");
            }
            assert!(!stale.exists(), "a stale leftover of this profile goes");
            assert!(fresh.exists(), "a recent one may be a write in progress");
            assert!(other.exists(), "another profile's is not touched");
            assert!(odd.exists(), "only the exact pattern is matched");
        }
    }

    #[test]
    fn something_that_is_not_a_regular_file_is_refused() {
        let (_tmp, store) = saved();
        std::fs::remove_file(store.path_for("p")).expect("rm");
        std::fs::create_dir(store.path_for("p")).expect("dir");
        refused_with(store.load("p"), "not a regular file");
    }

    #[test]
    fn a_corrupt_file_is_an_error_that_names_it() {
        let (_tmp, store) = saved();
        std::fs::write(store.path_for("p"), "not json").expect("write");
        let err = store.load("p").expect_err("corrupt");
        assert!(err.message.contains("is unreadable"), "{}", err.message);
        assert!(!err.message.starts_with(TOKEN_FILE_REFUSED));
        assert!(!err.message.contains("not json"));
    }

    #[test]
    fn a_file_for_another_profile_is_not_accepted() {
        let (_tmp, store) = saved();
        std::fs::copy(store.path_for("p"), store.path_for("q")).expect("copy");
        let err = store.load("q").expect_err("wrong profile");
        assert!(err.message.contains("is unreadable"), "{}", err.message);
    }

    #[test]
    fn two_profiles_are_two_files_and_odd_names_stay_inside() {
        let (_tmp, store) = store();
        for name in ["default", "client-b", "../../escape", "a/b", ""] {
            store.save(name, &token()).expect("save");
        }
        let names: Vec<String> = std::fs::read_dir(&store.dir)
            .expect("dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names.len(), 5, "{names:?}");
        assert!(
            names.iter().all(|n| n.len() == 69 && n.ends_with(".json")),
            "{names:?}"
        );
        assert!(store.load("../../escape").expect("load").is_some());
        assert!(store.delete("client-b").expect("delete"));
        assert!(store.load("default").expect("load").is_some());
        assert!(store.load("client-b").expect("load").is_none());
    }

    #[test]
    fn delete_removes_the_file_and_says_whether_there_was_one() {
        let (_tmp, store) = saved();
        assert!(store.delete("p").expect("delete"));
        assert!(!store.path_for("p").exists());
        assert!(!store.delete("p").expect("again"));
        let (_tmp, never) = self::store();
        assert!(!never.delete("p").expect("no directory"));
        assert!(!never.dir.exists(), "deleting creates nothing");
    }

    #[test]
    fn checking_availability_writes_no_token_and_leaves_no_file() {
        let (_tmp, store) = store();
        store.check_available("p").expect("available");
        assert_eq!(mode(&store.dir), 0o700);
        assert_eq!(std::fs::read_dir(&store.dir).expect("dir").count(), 0);
        assert!(store.load("p").expect("load").is_none());
    }

    #[test]
    fn reading_creates_nothing() {
        let (_tmp, store) = store();
        assert!(store.load("p").expect("load").is_none());
        assert!(!store.dir.exists());
    }

    #[test]
    fn network_file_systems_are_recognised_by_their_magic_number() {
        assert_eq!(network_file_system_for(0x6969), Some("NFS"));
        assert_eq!(network_file_system_for(0xFF53_4D42), Some("SMB/CIFS"));
        assert_eq!(network_file_system_for(0xEF53), None);
    }

    #[test]
    fn the_sessions_directory_is_outside_the_configuration_directory() {
        let sessions = sessions_dir().expect("dir");
        let config = crate::config::path().expect("config path");
        let config_dir = config.parent().expect("config dir");
        assert!(
            sessions.ends_with("sessions") || sessions.to_string_lossy().ends_with(".sessions")
        );
        assert!(
            !sessions.starts_with(config_dir),
            "{} is inside {}",
            sessions.display(),
            config_dir.display()
        );
    }
}
