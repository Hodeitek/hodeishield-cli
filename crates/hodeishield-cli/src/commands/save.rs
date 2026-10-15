// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.

//! Saving a downloaded file: the name to save it under, and a write that never leaves part of it.

use crate::failure::{Failure, Result};
use crate::output::clean;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Longest file name kept from the server, in bytes: well within every common file system's limit
/// of 255, with room for the temporary name next to it.
const MAX_NAME: usize = 200;

/// Names Windows keeps for devices, with any extension: `NUL.pdf` is the null device there.
const RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// The extension of a downloaded file: that of the format that was asked for, else the one the
/// answer's `Content-Type` says, else `pdf` (the API's default format). The name the server
/// suggests never decides it.
pub fn extension(requested: Option<&str>, content_type: Option<&str>) -> &'static str {
    let from = |value: &str| match value {
        "pdf" => Some("pdf"),
        "xlsx" => Some("xlsx"),
        _ => None,
    };
    requested
        .and_then(from)
        .or_else(|| {
            let media = content_type?.split(';').next()?.trim().to_ascii_lowercase();
            match media.as_str() {
                "application/pdf" => Some("pdf"),
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" => Some("xlsx"),
                _ => None,
            }
        })
        .unwrap_or("pdf")
}

/// The plain file name to save a download under. The name the server suggested is only a stem and
/// is never used as a path: only its last component is kept, every character other than an ASCII
/// letter, a digit, `.`, `_` and `-` becomes `_`, leading dots and dashes and trailing dots are
/// dropped, and everything from the first `.` on is cut, so the server cannot choose the extension:
/// it is always `extension`. When nothing usable is left (or the stem is too long, or a Windows
/// device name), the name is `report-<fallback>.<extension>`, the fallback reduced the same way, or
/// `report.<extension>`.
pub fn file_name(suggested: Option<&str>, fallback: &str, extension: &str) -> String {
    if let Some(stem) = suggested.and_then(stem) {
        return format!("{stem}.{extension}");
    }
    match stem(fallback) {
        Some(stem) => format!("report-{stem}.{extension}"),
        None => format!("report.{extension}"),
    }
}

/// `name` reduced to a plain file name: the last component, safe characters only, no leading dots
/// or dashes and no trailing dots.
fn reduce(name: &str) -> String {
    let last = name.rsplit(['/', '\\']).next().unwrap_or("");
    let reduced: String = last
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    reduced
        .trim_start_matches(['.', '-'])
        .trim_end_matches('.')
        .to_owned()
}

/// `name` reduced to a plain file name, or `None` when nothing usable is left.
fn plain(name: &str) -> Option<String> {
    let reduced = reduce(name);
    let stem = reduced.split('.').next().unwrap_or("");
    let usable = !reduced.is_empty()
        && reduced.len() <= MAX_NAME
        && reduced.chars().any(|c| c.is_ascii_alphanumeric())
        && !RESERVED.iter().any(|r| r.eq_ignore_ascii_case(stem));
    usable.then_some(reduced)
}

/// The part of `name` before its first dot, once reduced to a plain file name, or `None` when
/// nothing usable is left of it.
fn stem(name: &str) -> Option<String> {
    let reduced = reduce(name);
    let stem = reduced.split('.').next().unwrap_or("");
    let usable = stem.len() <= MAX_NAME
        && stem.chars().any(|c| c.is_ascii_alphanumeric())
        && !RESERVED.iter().any(|r| r.eq_ignore_ascii_case(stem));
    usable.then(|| stem.to_owned())
}

/// Whether something (a file, a directory, a link, even a broken one) is at `path`.
pub fn exists(path: &Path) -> bool {
    path.symlink_metadata().is_ok()
}

/// The refusal to replace what is at `path`.
pub fn already_exists(path: &Path) -> Failure {
    Failure::general(format!(
        "{} already exists; it was left as it is.",
        clean(&path.display().to_string())
    ))
    .hint("Add --force to replace it, or choose another path with --output.")
}

/// The refusal to replace what is at `path` once the report is already downloaded.
pub fn not_saved(path: &Path) -> Failure {
    Failure::general(format!(
        "The report was downloaded but not saved: {} already exists; it was left as it is.",
        clean(&path.display().to_string())
    ))
    .hint("Run the command again with --force to replace it, or with --output to choose another path.")
}

/// Checks that `directory` exists and that a file can be created in it, before anything is
/// downloaded for it.
pub fn check_writable(directory: &Path) -> Result<()> {
    if !directory.is_dir() {
        return Err(Failure::general(format!(
            "{} is not a directory.",
            clean(&directory.display().to_string())
        ))
        .hint("Create it, or choose another path with --output."));
    }
    Temporary::next_to(&directory.join("probe")).map(drop)
}

/// A temporary file that is removed when it goes out of scope, however that happens.
struct Temporary {
    path: PathBuf,
    file: Option<std::fs::File>,
}

impl Drop for Temporary {
    fn drop(&mut self) {
        // Closed first, as Windows does not remove an open file.
        self.file = None;
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Temporary {
    /// A new, empty file in the directory of `path`, under a name nothing else uses. On Unix only
    /// its owner can read or write it.
    fn next_to(path: &Path) -> Result<Self> {
        let directory = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        let base = path
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
        let base = plain(&base).unwrap_or_else(|| "download".to_owned());
        let mut last = None;
        for _ in 0..8 {
            let mut random = [0_u8; 6];
            getrandom::fill(&mut random).map_err(|e| {
                Failure::general(format!("Could not pick a temporary file name: {e}."))
            })?;
            let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
            let temporary = directory.join(format!(".{base}.{suffix}.part"));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            match options.open(&temporary) {
                Ok(file) => {
                    return Ok(Self {
                        path: temporary,
                        file: Some(file),
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => last = Some(e),
                Err(e) => return Err(cannot_write(path, &e)),
            }
        }
        Err(cannot_write(
            path,
            &last.unwrap_or_else(|| std::io::Error::other("no free temporary name")),
        ))
    }
}

/// Writes `bytes` to `path` so that the path never holds part of the file: they go to a new file
/// in the same directory, written and synced in full, which is then put in place. Without `force`
/// it is linked under the final name, which fails when something (a file, or a link, even a
/// broken one) is there, even if it appeared while this ran, and never follows a link; where hard
/// links are not available the path is claimed with an exclusive create and the file renamed over
/// it. With `force`, the rename replaces what is there, keeping its permissions on Unix.
pub fn write_new(path: &Path, bytes: &[u8], force: bool) -> Result<()> {
    let mut temporary = Temporary::next_to(path)?;
    if let Some(mut file) = temporary.file.take() {
        // Closed when it goes out of scope, before it is linked or renamed: Windows refuses to
        // rename an open file.
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|e| cannot_write(path, &e))?;
    }
    if force {
        replace(&temporary, path)
    } else {
        publish(&temporary, path)
    }
}

/// Renames the temporary file over `path`, with the permissions of the file it replaces.
fn replace(temporary: &Temporary, path: &Path) -> Result<()> {
    #[cfg(unix)]
    if let Ok(existing) = path.symlink_metadata()
        && existing.is_file()
    {
        std::fs::set_permissions(&temporary.path, existing.permissions())
            .map_err(|e| cannot_write(path, &e))?;
    }
    std::fs::rename(&temporary.path, path).map_err(|e| cannot_write(path, &e))
}

/// Puts the temporary file at `path` without replacing anything.
fn publish(temporary: &Temporary, path: &Path) -> Result<()> {
    match std::fs::hard_link(&temporary.path, path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(already_exists(path)),
        // Not every file system has hard links (FAT, some network shares).
        Err(_) => publish_by_placeholder(temporary, path),
    }
}

/// [`publish`] where there are no hard links: the path is claimed with an exclusive create, then
/// the temporary file is renamed over that empty file.
fn publish_by_placeholder(temporary: &Temporary, path: &Path) -> Result<()> {
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(already_exists(path));
        }
        Err(e) => return Err(cannot_write(path, &e)),
    }
    std::fs::rename(&temporary.path, path).map_err(|e| {
        // The empty file claimed above; nothing else is removed.
        let _ = std::fs::remove_file(path);
        cannot_write(path, &e)
    })
}

fn cannot_write(path: &Path, error: &std::io::Error) -> Failure {
    Failure::general(format!(
        "Could not write {}: {error}.",
        clean(&path.display().to_string())
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(suggested: &str) -> String {
        file_name(
            Some(suggested),
            "0b8f2a52-6a0e-4d5c-9d3e-1f2a3b4c5d6e",
            "pdf",
        )
    }

    #[test]
    fn a_plain_name_is_kept() {
        assert_eq!(name("monthly-2026-09.pdf"), "monthly-2026-09.pdf");
        assert_eq!(name("monthly-2026-09"), "monthly-2026-09.pdf");
    }

    #[test]
    fn the_server_cannot_choose_the_extension() {
        assert_eq!(name("conftest.py"), "conftest.pdf");
        assert_eq!(name("x.library-ms"), "x.pdf");
        assert_eq!(name("a.pdf.exe"), "a.pdf");
        assert_eq!(name("a.b.pdf"), "a.pdf");
        assert_eq!(name("Board_Report.v2.xlsx"), "Board_Report.pdf");
        assert_eq!(name("evil.url"), "evil.pdf");
        assert_eq!(
            file_name(Some("board.pdf"), "r-1", "xlsx"),
            "board.xlsx",
            "the extension is the one of the format"
        );
    }

    #[test]
    fn a_name_with_no_stem_left_falls_back_to_the_id() {
        for suggested in ["_.pdf", "__.exe", "...", "NUL.exe"] {
            assert_eq!(
                file_name(Some(suggested), "r-1", "pdf"),
                "report-r-1.pdf",
                "{suggested:?}"
            );
        }
    }

    #[test]
    fn the_extension_comes_from_the_format_then_the_content_type() {
        let xlsx = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
        assert_eq!(extension(Some("xlsx"), Some("application/pdf")), "xlsx");
        assert_eq!(extension(Some("pdf"), Some(xlsx)), "pdf");
        assert_eq!(extension(None, Some(xlsx)), "xlsx");
        assert_eq!(extension(None, Some("Application/PDF; charset=x")), "pdf");
        assert_eq!(extension(None, Some("text/html")), "pdf");
        assert_eq!(extension(Some("docx"), Some(xlsx)), "xlsx");
        assert_eq!(extension(None, None), "pdf");
    }

    #[test]
    fn only_the_last_component_is_kept() {
        assert_eq!(name("../../etc/passwd"), "passwd.pdf");
        assert_eq!(name("a/b\\c.pdf"), "c.pdf");
        assert_eq!(name("C:\\Windows\\system.ini"), "system.pdf");
        assert_eq!(name("/absolute/report.pdf"), "report.pdf");
    }

    #[test]
    fn unsafe_characters_become_underscores() {
        assert_eq!(name("a\u{1b}[31mb.pdf"), "a__31mb.pdf");
        assert_eq!(name("re port\r\n.pdf"), "re_port__.pdf");
        assert_eq!(name("informe\u{202e}fdp.exe"), "informe_fdp.pdf");
        assert_eq!(name("a:b*c?.pdf"), "a_b_c_.pdf");
        assert_eq!(name("año.pdf"), "a_o.pdf");
    }

    #[test]
    fn hidden_option_like_and_dot_names_are_not_kept_as_such() {
        assert_eq!(name(".bashrc"), "bashrc.pdf");
        assert_eq!(name("-rf.pdf"), "rf.pdf");
        assert_eq!(name("report.pdf..."), "report.pdf");
    }

    #[test]
    fn nothing_usable_falls_back_to_the_id() {
        let fallback = "report-0b8f2a52-6a0e-4d5c-9d3e-1f2a3b4c5d6e.pdf";
        for suggested in [
            "..",
            ".",
            "",
            "a/",
            "../..",
            "\u{1b}\u{7}",
            "___",
            "NUL.pdf",
            "con",
        ] {
            assert_eq!(name(suggested), fallback, "{suggested:?}");
        }
        assert_eq!(name(&"a".repeat(MAX_NAME + 1)), fallback);
        assert_eq!(
            file_name(None, "0b8f2a52-6a0e-4d5c-9d3e-1f2a3b4c5d6e", "xlsx"),
            "report-0b8f2a52-6a0e-4d5c-9d3e-1f2a3b4c5d6e.xlsx"
        );
    }

    #[test]
    fn the_fallback_is_reduced_too() {
        assert_eq!(file_name(None, "../x", "pdf"), "report-x.pdf");
        assert_eq!(file_name(None, "..", "pdf"), "report.pdf");
    }

    #[test]
    fn an_existing_file_is_left_alone_without_force_and_replaced_with_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.pdf");
        write_new(&path, b"first", false).expect("new file");
        assert_eq!(std::fs::read(&path).expect("read"), b"first");
        let failure = write_new(&path, b"second", false).expect_err("exists");
        assert!(
            failure.message.contains("already exists"),
            "{}",
            failure.message
        );
        assert_eq!(std::fs::read(&path).expect("read"), b"first");
        write_new(&path, b"third", true).expect("forced");
        assert_eq!(std::fs::read(&path).expect("read"), b"third");
        let left: Vec<_> = std::fs::read_dir(dir.path())
            .expect("list")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(left, ["report.pdf"], "no temporary file is left behind");
    }

    #[test]
    fn publishing_refuses_an_existing_file_and_leaves_no_temporary_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.pdf");
        std::fs::write(&path, b"mine").expect("write");
        let temporary = Temporary::next_to(&path).expect("temporary");
        let failure = publish(&temporary, &path).expect_err("hard link refuses");
        assert!(failure.message.contains("already exists"));
        let failure = publish_by_placeholder(&temporary, &path).expect_err("placeholder refuses");
        assert!(failure.message.contains("already exists"));
        drop(temporary);
        assert_eq!(std::fs::read(&path).expect("read"), b"mine");
        assert_eq!(entries(dir.path()), ["report.pdf"]);
        write_new(&path, b"other", false).expect_err("exists");
        assert_eq!(entries(dir.path()), ["report.pdf"]);
    }

    #[test]
    fn the_placeholder_fallback_publishes_the_whole_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.pdf");
        let mut temporary = Temporary::next_to(&path).expect("temporary");
        let mut file = temporary.file.take().expect("file");
        file.write_all(b"whole").expect("write");
        drop(file);
        publish_by_placeholder(&temporary, &path).expect("published");
        drop(temporary);
        assert_eq!(std::fs::read(&path).expect("read"), b"whole");
        assert_eq!(entries(dir.path()), ["report.pdf"]);
    }

    #[test]
    fn a_failed_write_leaves_nothing_behind() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("missing").join("report.pdf");
        write_new(&path, b"x", false).expect_err("no directory");
        assert!(entries(dir.path()).is_empty());
        // A directory where the file should go: the rename is refused.
        let path = dir.path().join("taken");
        std::fs::create_dir(&path).expect("mkdir");
        write_new(&path, b"x", true).expect_err("a directory");
        assert_eq!(entries(dir.path()), ["taken"]);
    }

    #[test]
    fn a_directory_is_checked_before_a_download() {
        let dir = tempfile::tempdir().expect("tempdir");
        check_writable(dir.path()).expect("writable");
        assert!(entries(dir.path()).is_empty());
        let missing = dir.path().join("nope");
        let failure = check_writable(&missing).expect_err("missing");
        assert!(failure.message.contains("is not a directory"));
    }

    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .expect("list")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[cfg(unix)]
    #[test]
    fn a_saved_file_is_readable_by_its_owner_only_and_force_keeps_the_mode_it_had() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| p.metadata().expect("metadata").permissions().mode() & 0o777;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.pdf");
        write_new(&path, b"first", false).expect("new file");
        assert_eq!(mode(&path), 0o600);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).expect("chmod");
        write_new(&path, b"second", true).expect("forced");
        assert_eq!(std::fs::read(&path).expect("read"), b"second");
        assert_eq!(mode(&path), 0o640);
        assert_eq!(entries(dir.path()), ["report.pdf"]);
    }
}
