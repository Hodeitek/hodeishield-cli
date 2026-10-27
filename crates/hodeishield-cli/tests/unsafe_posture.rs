// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.

//! The `unsafe` posture of the workspace, enforced.
//!
//! The workspace lint denies `unsafe` code, and exactly one module (the Windows-only handle
//! helper) may switch it back on. These tests fail when the lint is weakened or when any other
//! source file opts out of it, so widening the exception is always a deliberate edit of this file.

use std::fs;
use std::path::{Path, PathBuf};

/// The only file that may opt out of the lint, relative to the workspace root.
const EXCEPTION: &str = "crates/hodeishield-cli/src/std_handles.rs";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read_dir") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn workspace_lint_denies_unsafe_code() {
    let manifest = fs::read_to_string(root().join("Cargo.toml")).expect("Cargo.toml");
    let value = manifest
        .lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix("unsafe_code"))
        .map(|rest| rest.trim_start_matches([' ', '=']).trim().to_owned())
        .expect("the workspace sets the unsafe_code lint");
    assert!(
        value == "\"deny\"" || value == "\"forbid\"",
        "workspace unsafe_code lint is {value}, expected \"deny\" or \"forbid\""
    );
}

#[test]
fn only_the_exception_opts_out_of_the_lint() {
    let root = root();
    let mut files = Vec::new();
    for dir in ["crates", "xtask"] {
        rust_files(&root.join(dir), &mut files);
    }
    assert!(files.len() > 10, "found only {} source files", files.len());

    // Built in pieces so that this file does not contain the text it looks for.
    let needles = [
        format!("{}(unsafe_code", "allow"),
        format!("{}(unsafe_code", "expect"),
    ];
    let exception = root.join(EXCEPTION);
    let offenders: Vec<_> = files
        .iter()
        .filter(|f| **f != exception)
        .filter(|f| {
            let text: String = fs::read_to_string(f)
                .expect("read source")
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            needles.iter().any(|n| text.contains(n.as_str()))
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "these files opt out of the unsafe_code lint: {offenders:?}"
    );
}
