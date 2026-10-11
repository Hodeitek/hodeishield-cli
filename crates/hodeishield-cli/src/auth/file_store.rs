// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.

//! The opt-in plain-text token store: one JSON file per profile, readable only by its owner.
//!
//! This is the weaker of the two stores and is never chosen on its own: it is used only when
//! `HODEISHIELD_TOKEN_STORE=plaintext-file` or the global `token_store` setting says so. There is
//! no fallback in either direction (see `docs/decisions/0001-sign-in-without-a-keychain.md`).
//!
//! Files live in the platform's state directory (`$XDG_STATE_HOME/hodeishield/sessions/` on Linux),
//! not in the configuration directory, so a copied or synced configuration never carries a token.
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
    // `state_dir` exists on Linux and the BSDs; macOS has only the application support directory.
    Ok(dirs
        .state_dir()
        .unwrap_or_else(|| dirs.data_local_dir())
        .join("sessions"))
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
    use std::fs::{File, Metadata, OpenOptions};
    use std::io::{Read, Write};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::{Path, PathBuf};

    /// Biggest file read: a token payload is well under a kilobyte.
    const MAX_BYTES: u64 = 64 * 1024;

    /// The effective user id of this process.
    fn euid() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    /// What is wrong with a file or directory, judged from its own metadata (never a followed
    /// link): `None` when it can be trusted.
    pub(super) fn problem(meta: &Metadata, want_dir: bool, euid: u32) -> Option<(String, String)> {
        let kind = if want_dir { "directory" } else { "file" };
        let fix_mode = if want_dir { "700" } else { "600" };
        if meta.file_type().is_symlink() {
            return Some((
                "is a symbolic link, which is never followed".into(),
                String::new(),
            ));
        }
        let right_type = if want_dir {
            meta.is_dir()
        } else {
            meta.is_file()
        };
        if !right_type {
            return Some((format!("is not a regular {kind}"), String::new()));
        }
        if meta.uid() != euid {
            return Some((
                format!("belongs to another user (uid {}), not to you", meta.uid()),
                String::new(),
            ));
        }
        let mode = meta.mode() & 0o777;
        if mode & 0o077 != 0 {
            return Some((
                format!("is accessible to other users (mode {mode:03o}); it must be {fix_mode}"),
                format!(
                    "If you own it and nobody else read it, `chmod {fix_mode}` fixes it; a token that may have been read should be revoked from the app."
                ),
            ));
        }
        None
    }

    fn check(path: &Path, meta: &Metadata, want_dir: bool) -> Result<()> {
        match problem(meta, want_dir, euid()) {
            None => Ok(()),
            Some((reason, fix)) => Err(refused(path, &reason, Some(fix).filter(|f| !f.is_empty()))),
        }
    }

    /// Looks at a path without following a link at its end. `None` when it is absent.
    fn look(path: &Path) -> Result<Option<Metadata>> {
        match std::fs::symlink_metadata(path) {
            Ok(meta) => Ok(Some(meta)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_failure("Cannot look at", path, &e)),
        }
    }

    /// The sessions directory, checked. `None` when absent and `create` is false; created with
    /// mode 0700 otherwise.
    fn dir(store: &FileStore, create: bool) -> Result<Option<()>> {
        if let Some(meta) = look(&store.dir)? {
            check(&store.dir, &meta, true)?;
            return Ok(Some(()));
        }
        if !create {
            return Ok(None);
        }
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&store.dir)
            .map_err(|e| io_failure("Cannot create", &store.dir, &e))?;
        // Whatever the umask or a concurrent creator did, it is judged like an existing one.
        let meta = look(&store.dir)?.ok_or_else(|| {
            Failure::general(format!(
                "{} disappeared while it was created.",
                store.dir.display()
            ))
        })?;
        check(&store.dir, &meta, true)?;
        Ok(Some(()))
    }

    /// Opens a file for reading and judges the opened handle, which must be the very file that
    /// was looked at (a swap in between is refused).
    fn open_checked(path: &Path) -> Result<Option<File>> {
        let Some(seen) = look(path)? else {
            return Ok(None);
        };
        check(path, &seen, false)?;
        let file = match File::open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io_failure("Cannot read", path, &e)),
        };
        let opened = file
            .metadata()
            .map_err(|e| io_failure("Cannot read", path, &e))?;
        if (opened.dev(), opened.ino()) != (seen.dev(), seen.ino()) {
            return Err(refused(path, "changed while it was being opened", None));
        }
        check(path, &opened, false)?;
        Ok(Some(file))
    }

    pub(super) fn load(store: &FileStore, profile: &str) -> Result<Option<StoredToken>> {
        if dir(store, false)?.is_none() {
            return Ok(None);
        }
        let path = store.path_for(profile);
        let Some(file) = open_checked(&path)? else {
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

    /// Removes the temporary file unless it was renamed into place.
    struct Temp<'a> {
        path: &'a Path,
        armed: bool,
    }

    impl Drop for Temp<'_> {
        fn drop(&mut self) {
            if self.armed {
                let _ = std::fs::remove_file(self.path);
            }
        }
    }

    fn temp_path(store: &FileStore, profile: &str) -> Result<PathBuf> {
        let mut random = [0u8; 8];
        getrandom::fill(&mut random)
            .map_err(|e| Failure::general(format!("cannot get random bytes: {e}")))?;
        let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
        Ok(store.dir.join(format!(
            ".{}.{suffix}.tmp",
            &super::file_name(profile)[..16]
        )))
    }

    /// Writes `bytes` to a new 0600 file next to `path` and renames it over `path`.
    fn write_atomically(store: &FileStore, profile: &str, path: &Path, bytes: &[u8]) -> Result<()> {
        let temp = temp_path(store, profile)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
            .map_err(|e| io_failure("Cannot create", &temp, &e))?;
        let mut guard = Temp {
            path: &temp,
            armed: true,
        };
        // The umask can only remove bits from 0600; say 0600 whatever it was.
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .and_then(|()| file.write_all(bytes))
            .and_then(|()| file.sync_all())
            .map_err(|e| io_failure("Cannot write", &temp, &e))?;
        drop(file);
        std::fs::rename(&temp, path).map_err(|e| io_failure("Cannot replace", path, &e))?;
        guard.armed = false;
        sync_dir(&store.dir);
        Ok(())
    }

    /// Makes a rename or removal durable. Best effort: not every file system allows it.
    fn sync_dir(dir: &Path) {
        if let Ok(handle) = File::open(dir) {
            let _ = handle.sync_all();
        }
    }

    pub(super) fn save(store: &FileStore, profile: &str, token: &StoredToken) -> Result<()> {
        dir(store, true)?;
        let path = store.path_for(profile);
        // An existing file is judged before it is replaced, even though it will not be read.
        if let Some(meta) = look(&path)? {
            check(&path, &meta, false)?;
        }
        let record = Record {
            profile: profile.to_owned(),
            payload: token.to_payload(),
        };
        let mut text = serde_json::to_string(&record)
            .map_err(|e| Failure::general(format!("cannot encode the sign-in: {e}")))?;
        text.push('\n');
        write_atomically(store, profile, &path, text.as_bytes())
    }

    pub(super) fn delete(store: &FileStore, profile: &str) -> Result<bool> {
        if dir(store, false)?.is_none() {
            return Ok(false);
        }
        let path = store.path_for(profile);
        let Some(meta) = look(&path)? else {
            return Ok(false);
        };
        check(&path, &meta, false)?;
        match std::fs::remove_file(&path) {
            Ok(()) => {
                sync_dir(&store.dir);
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(io_failure("Cannot remove", &path, &e)),
        }
    }

    /// Proves the store can be used: the directory exists with the right owner and mode (it is
    /// created if absent), the profile's file, if any, is trustworthy, and an empty file can be
    /// created and removed there. No token is written.
    pub(super) fn check_available(store: &FileStore, profile: &str) -> Result<()> {
        dir(store, true)?;
        let path = store.path_for(profile);
        if let Some(meta) = look(&path)? {
            check(&path, &meta, false)?;
        }
        let probe = temp_path(store, profile)?;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&probe)
            .map_err(|e| {
                Failure::general(format!(
                    "the plain-text token store cannot be used: cannot write in {}: {e}",
                    store.dir.display()
                ))
                .hint("Use the system keychain or a tenant API key in HODEISHIELD_API_KEY.")
            })?;
        let _ = std::fs::remove_file(&probe);
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
            refused_with(store.load("p"), "must be 700");
            refused_with(store.save("p", &token()), "must be 700");
            refused_with(store.delete("p"), "must be 700");
            refused_with(store.check_available("p"), "must be 700");
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
        let meta = std::fs::symlink_metadata(store.path_for("p")).expect("meta");
        let me = meta.uid();
        assert!(unix::problem(&meta, false, me).is_none());
        let (reason, _) = unix::problem(&meta, false, me.wrapping_add(1)).expect("another owner");
        assert!(reason.contains("belongs to another user"), "{reason}");
        let dir_meta = std::fs::symlink_metadata(&store.dir).expect("meta");
        assert!(unix::problem(&dir_meta, true, me.wrapping_add(1)).is_some());
        assert_eq!(rustix::process::geteuid().as_raw(), me);
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
    fn the_state_directory_is_not_the_configuration_directory() {
        let dir = sessions_dir().expect("dir");
        assert!(dir.ends_with("sessions"));
        assert!(
            !dir.to_string_lossy().contains("/.config/"),
            "{}",
            dir.display()
        );
    }
}
