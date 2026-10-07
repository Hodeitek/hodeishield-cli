#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
"""Compares openapi/v1.json with the document the API publishes and, when their content differs,
replaces the vendored copy and updates what records it (openapi/README.md, xtask's EXPECTED_SHA256).

Usage: openapi-sync.py <url> <out-dir>

Content means the JSON value: key order and whitespace do not count. On a difference the published
bytes are written unchanged, as openapi/README.md requires, and <out-dir> receives `old.json` (the
previous copy), `summary.md` and `version.txt`. Exits 0 in both cases and prints `changed=true` or
`changed=false`; anything wrong with the published document is an error (exit 1).

Run from the repository root. Uses only the standard library.
"""

import hashlib
import json
import pathlib
import re
import sys
import urllib.request

SPEC = pathlib.Path("openapi/v1.json")
README = pathlib.Path("openapi/README.md")
XTASK = pathlib.Path("xtask/src/main.rs")
MAX_BYTES = 5 * 1024 * 1024
USER_AGENT = "hodeishield-cli-openapi-sync (+https://github.com/Hodeitek/hodeishield-cli)"


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=30) as response:
        body = response.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise SystemExit(f"error: {url} is larger than {MAX_BYTES} bytes")
    return body


def check(document, url):
    if not str(document.get("openapi", "")).startswith("3."):
        raise SystemExit(f"error: {url} is not an OpenAPI 3 document")
    version = document.get("info", {}).get("version")
    # It ends up in a branch commit, a pull request title and workflow outputs: plain text only.
    if not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,39}", version):
        raise SystemExit(f"error: {url} has a missing or unusual info.version")
    if not document.get("paths"):
        raise SystemExit(f"error: {url} has no paths")


def canonical(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def operations(document):
    methods = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
    return {
        f"{method.upper()} {path}"
        for path, item in document["paths"].items()
        for method in item
        if method in methods
    }


def main():
    url, out = sys.argv[1], pathlib.Path(sys.argv[2])
    published = fetch(url)
    try:
        new = json.loads(published)
    except ValueError as e:
        raise SystemExit(f"error: {url} is not JSON: {e}")
    check(new, url)
    current = SPEC.read_bytes()
    old = json.loads(current)
    if canonical(new) == canonical(old):
        print("changed=false")
        return

    out.mkdir(parents=True, exist_ok=True)
    (out / "old.json").write_bytes(current)
    SPEC.write_bytes(published)
    digest = hashlib.sha256(published).hexdigest()
    old_digest = hashlib.sha256(current).hexdigest()
    version, old_version = new["info"]["version"], old["info"]["version"]
    ops, old_ops = operations(new), operations(old)
    non_get = sorted(op for op in ops if not op.startswith("GET "))
    count = f"{len(ops)}, all `GET`" if not non_get else str(len(ops))

    readme = README.read_text()
    readme = re.sub(r"(\| `info\.version` \| `)[^`]*(` \|)", rf"\g<1>{version}\g<2>", readme)
    readme = re.sub(r"(\| SHA-256 \| `)[0-9a-f]{64}(` \|)", rf"\g<1>{digest}\g<2>", readme)
    readme = re.sub(r"(\| Operations \| )[^|\n]*?( \|)", rf"\g<1>{count}\g<2>", readme)
    README.write_text(readme)
    xtask = XTASK.read_text()
    xtask, replaced = re.subn(
        r'(const EXPECTED_SHA256: &str = ")[0-9a-f]{64}(";)', rf"\g<1>{digest}\g<2>", xtask
    )
    if replaced != 1:
        raise SystemExit(f"error: EXPECTED_SHA256 not found in {XTASK}")
    XTASK.write_text(xtask)

    lines = [
        f"- `info.version`: `{old_version}` → `{version}`",
        f"- SHA-256: `{old_digest[:12]}…` → `{digest[:12]}…`",
        f"- Operations: {len(old_ops)} → {len(ops)}",
    ]
    for label, items in (("Added", sorted(ops - old_ops)), ("Removed", sorted(old_ops - ops))):
        if items:
            lines.append(f"- {label} operations: " + ", ".join(f"`{op}`" for op in items))
    if non_get:
        lines.append("- **Not read-only**: " + ", ".join(f"`{op}`" for op in non_get))
    (out / "summary.md").write_text("\n".join(lines) + "\n")
    (out / "version.txt").write_text(version + "\n")
    print("changed=true")


if __name__ == "__main__":
    main()
