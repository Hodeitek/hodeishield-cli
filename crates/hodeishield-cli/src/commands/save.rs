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

/// The plain file name to save a download under. The name the server suggested is never used as a
/// path: only its last component is kept, every character other than an ASCII letter, a digit, `.`,
/// `_` and `-` becomes `_`, and leading dots and dashes and trailing dots are dropped. When nothing
/// usable is left (or the name is too long, or a Windows device name), the name is
/// `report-<fallback>.<extension>`, the fallback reduced the same way, or `report.<extension>`.
pub fn file_name(suggested: Option<&str>, fallback: &str, extension: &str) -> String {
    if let Some(name) = suggested.and_then(plain) {
        return name;
    }
    match plain(fallback) {
        Some(stem) => format!("report-{stem}.{extension}"),
        None => format!("report.{extension}"),
    }
}

/// `name` reduced to a plain file name, or `None` when nothing usable is left.
fn plain(name: &str) -> Option<String> {
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
    let reduced = reduced.trim_start_matches(['.', '-']).trim_end_matches('.');
    let stem = reduced.split('.').next().unwrap_or("");
    let usable = !reduced.is_empty()
        && reduced.len() <= MAX_NAME
        && reduced.chars().any(|c| c.is_ascii_alphanumeric())
        && !RESERVED.iter().any(|r| r.eq_ignore_ascii_case(stem));
    usable.then(|| reduced.to_owned())
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

/// Writes `bytes` to `path` so that the path never holds part of the file: they go to a new file
/// in the same directory, which is then renamed into place. Without `force`, the path is first
/// claimed with an exclusive create, so an existing file (or link) is never replaced, even one that
/// appears while this runs; with it, the rename replaces what is there.
pub fn write_new(path: &Path, bytes: &[u8], force: bool) -> Result<()> {
    if !force {
        match OpenOptions::new().write(true).create_new(true).open(path) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(already_exists(path));
            }
            Err(e) => return Err(cannot_write(path, &e)),
        }
    }
    let written = write_and_rename(path, bytes);
    if written.is_err() && !force {
        // The empty file claimed above; nothing else is removed.
        let _ = std::fs::remove_file(path);
    }
    written
}

fn write_and_rename(path: &Path, bytes: &[u8]) -> Result<()> {
    let (temporary, mut file) = temporary_next_to(path)?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    // Closed before the rename, which Windows refuses on an open file.
    drop(file);
    written
        .and_then(|()| std::fs::rename(&temporary, path))
        .map_err(|e| {
            let _ = std::fs::remove_file(&temporary);
            cannot_write(path, &e)
        })
}

/// A new, empty file in the directory of `path`, under a name nothing else uses.
fn temporary_next_to(path: &Path) -> Result<(PathBuf, std::fs::File)> {
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
        getrandom::fill(&mut random)
            .map_err(|e| Failure::general(format!("Could not pick a temporary file name: {e}.")))?;
        let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let temporary = directory.join(format!(".{base}.{suffix}.part"));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
        {
            Ok(file) => return Ok((temporary, file)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => last = Some(e),
            Err(e) => return Err(cannot_write(path, &e)),
        }
    }
    Err(cannot_write(
        path,
        &last.unwrap_or_else(|| std::io::Error::other("no free temporary name")),
    ))
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
        assert_eq!(name("Board_Report.v2.xlsx"), "Board_Report.v2.xlsx");
    }

    #[test]
    fn only_the_last_component_is_kept() {
        assert_eq!(name("../../etc/passwd"), "passwd");
        assert_eq!(name("a/b\\c.pdf"), "c.pdf");
        assert_eq!(name("C:\\Windows\\system.ini"), "system.ini");
        assert_eq!(name("/absolute/report.pdf"), "report.pdf");
    }

    #[test]
    fn unsafe_characters_become_underscores() {
        assert_eq!(name("a\u{1b}[31mb.pdf"), "a__31mb.pdf");
        assert_eq!(name("re port\r\n.pdf"), "re_port__.pdf");
        assert_eq!(name("informe\u{202e}fdp.exe"), "informe_fdp.exe");
        assert_eq!(name("a:b*c?.pdf"), "a_b_c_.pdf");
        assert_eq!(name("año.pdf"), "a_o.pdf");
    }

    #[test]
    fn hidden_option_like_and_dot_names_are_not_kept_as_such() {
        assert_eq!(name(".bashrc"), "bashrc");
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
}
