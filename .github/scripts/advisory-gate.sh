#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
#
# The known-vulnerabilities check of a release (CONTRIBUTING.md, "Known vulnerabilities at
# release"): cargo deny and cargo audit against the RustSec advisory database, letting through only
# the advisories accepted in deny.toml with a reason and a review date that has not passed.
#
#   advisory-gate.sh
#
# Runs in the repository root, with cargo-deny and cargo-audit installed. Fails if either tool
# reports an advisory that is not accepted, or if the accepted list is not valid. On success, the
# last line of the output is the one-line result that the release notes carry.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)

python3 "$here/advisory-exceptions.py" check
mapfile -t accepted < <(python3 "$here/advisory-exceptions.py" audit-args)

cargo deny check advisories
cargo audit ${accepted[@]+"${accepted[@]}"}

deny_version=$(cargo deny --version | awk '{ print $2 }')
audit_version=$(cargo audit --version | awk '{ print $2 }')
db=$(git -C "$HOME/.cargo/advisory-db" rev-parse --short=12 HEAD)
ids=""
for ((i = 1; i < ${#accepted[@]}; i += 2)); do
  ids="${ids:+$ids, }${accepted[i]}"
done

result="No unaddressed security advisory for this commit (cargo-deny $deny_version, cargo-audit $audit_version, RustSec advisory database at $db)"
if [ -n "$ids" ]; then
  result="$result; accepted with a written reason in deny.toml: $ids"
fi
echo "$result."
