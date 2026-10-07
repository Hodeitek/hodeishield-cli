#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
"""Writes the issue body that reports a difference between openapi/v1.json and the published document.

Usage: openapi-drift-report.py <oasdiff> <dir> <run-url>

<dir> is the output directory of openapi-sync.py (it holds `published.json` and `vendored.json`);
`body.md` is written there and `breaking=true|false` is printed for $GITHUB_OUTPUT.

oasdiff runs in both directions, since either side may be the one that is behind:
  vendored -> published  breaking: a client built from openapi/v1.json may fail against the published document
  published -> vendored  breaking: a client built from the published document may fail against openapi/v1.json
Breaking means an oasdiff change of level ERR, as `oasdiff breaking --fail-on ERR` counts it.

The text oasdiff prints comes from the published document, so it is untrusted: it is truncated and
only ever placed inside a code fence longer than any backtick run it contains. Any failure of
oasdiff is an error (exit 1), never a quiet pass.
"""

import hashlib
import json
import pathlib
import re
import subprocess
import sys

MAX_CHARS = 8000
ERR_LEVEL = 3


def run(oasdiff, directory, *args):
    result = subprocess.run(
        [oasdiff, *args], cwd=directory, capture_output=True, text=True, errors="replace", timeout=300
    )
    if result.returncode != 0:
        raise SystemExit(f"error: oasdiff {args[0]} failed (exit {result.returncode}): {result.stderr.strip()[:500]}")
    return result.stdout


def breaking(oasdiff, directory, base, revision):
    try:
        changes = json.loads(run(oasdiff, directory, "breaking", base, revision, "-f", "json") or "[]")
    except ValueError as e:
        raise SystemExit(f"error: oasdiff breaking printed output that is not JSON: {e}")
    if not isinstance(changes, list):
        raise SystemExit("error: oasdiff breaking printed an unexpected document")
    return [c for c in changes if isinstance(c, dict) and c.get("level", 0) >= ERR_LEVEL]


def clean(text):
    return re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", text)


def fenced(text):
    """Truncates `text` and wraps it in a fence that no backtick run inside it can close."""
    text = clean(text).strip()
    note = ""
    if len(text) > MAX_CHARS:
        text, note = text[:MAX_CHARS], "\n[truncated]"
    fence = "`" * max(3, max((len(m) for m in re.findall(r"`+", text)), default=0) + 1)
    return f"{fence}text\n{text}{note}\n{fence}"


def info_version(path):
    return json.loads(path.read_text())["info"]["version"]


def main():
    oasdiff, directory, run_url = sys.argv[1], pathlib.Path(sys.argv[2]), sys.argv[3]
    published = directory / "published.json"
    digest = hashlib.sha256(published.read_bytes()).hexdigest()
    vendored_digest = hashlib.sha256((directory / "vendored.json").read_bytes()).hexdigest()
    forward = breaking(oasdiff, directory, "vendored.json", "published.json")
    backward = breaking(oasdiff, directory, "published.json", "vendored.json")
    changelog = run(oasdiff, directory, "changelog", "published.json", "vendored.json")
    summary = run(oasdiff, directory, "summary", "published.json", "vendored.json")

    def lines(changes):
        return "\n".join(f"{c.get('operation', '')} {c.get('path', '')}: {c.get('text', '')}".strip() for c in changes) or "none"

    def verdict(changes):
        return f"**yes**, {len(changes)} breaking change(s)" if changes else "no"

    body = f"""The published `/v1` OpenAPI document differs in content from the vendored `openapi/v1.json`. Key order and whitespace are not compared.

| | Published document | `openapi/v1.json` |
|---|---|---|
| `info.version` | `{info_version(published)}` | `{info_version(directory / "vendored.json")}` |
| SHA-256 | `{digest}` | `{vendored_digest}` |

**Breaking changes, according to [oasdiff](https://github.com/oasdiff/oasdiff)**

- From `openapi/v1.json` to the published document (a client built from the vendored copy may fail against the published one): {verdict(forward)}
- From the published document to `openapi/v1.json` (a client built from the published document may fail against the vendored copy): {verdict(backward)}

**Breaking changes from `openapi/v1.json` to the published document**

{fenced(lines(forward))}

**Breaking changes from the published document to `openapi/v1.json`**

{fenced(lines(backward))}

**Summary, published to vendored**

{fenced(summary)}

**Changelog, published to vendored**

{fenced(changelog)}

The vendored document is not updated automatically. Decide whether the API or the vendored copy is behind, then fix that side.

Reported by the OpenAPI sync workflow: {run_url}

<!-- openapi-drift:{digest} -->
"""
    (directory / "body.md").write_text(body)
    print(f"breaking={'true' if forward or backward else 'false'}")
    print(f"published_sha256={digest}")


if __name__ == "__main__":
    main()
