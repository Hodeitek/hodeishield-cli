#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
"""Compares openapi/v1.json with the document the API publishes. Changes nothing in the repository.

Usage: openapi-sync.py <url> <out-dir>

Content means the JSON value: key order and whitespace do not count. <out-dir> receives
`published.json` (the published bytes, unchanged) and `vendored.json` (a copy of openapi/v1.json).
Prints `changed=true` or `changed=false` and the two `info.version` values, as `key=value` lines
fit for $GITHUB_OUTPUT, and exits 0 in both cases; anything wrong with the published document, or
a failure to fetch it, is an error (exit 1) so the caller fails closed.

Run from the repository root. Uses only the standard library.
"""

import json
import pathlib
import re
import sys
import urllib.request

SPEC = pathlib.Path("openapi/v1.json")
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
    # It ends up in an issue and in workflow outputs: plain text only.
    if not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,39}", version):
        raise SystemExit(f"error: {url} has a missing or unusual info.version")
    if not document.get("paths"):
        raise SystemExit(f"error: {url} has no paths")


def local_refs_only(node, url, where="#"):
    """Refuses any `$ref` that is not a pointer into the document itself. oasdiff, which compares
    the old and new documents, would otherwise read the file or fetch the URL a `$ref` names and
    could copy it into the public pull request."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "$ref" and not (isinstance(value, str) and value.startswith("#/")):
                raise SystemExit(f"error: {url} has a non-local $ref at {where}: {str(value)[:80]!r}")
            local_refs_only(value, url, f"{where}/{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            local_refs_only(value, url, f"{where}/{index}")


def canonical(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def main():
    url, out = sys.argv[1], pathlib.Path(sys.argv[2])
    try:
        published = fetch(url)
    except OSError as e:
        raise SystemExit(f"error: cannot fetch {url}: {e}")
    try:
        new = json.loads(published)
    except ValueError as e:
        raise SystemExit(f"error: {url} is not JSON: {e}")
    check(new, url)
    local_refs_only(new, url)
    current = SPEC.read_bytes()
    old = json.loads(current)
    out.mkdir(parents=True, exist_ok=True)
    (out / "published.json").write_bytes(published)
    (out / "vendored.json").write_bytes(current)
    changed = canonical(new) != canonical(old)
    print(f"changed={'true' if changed else 'false'}")
    print(f"published_version={new['info']['version']}")
    print(f"vendored_version={old['info'].get('version')}")


if __name__ == "__main__":
    main()
