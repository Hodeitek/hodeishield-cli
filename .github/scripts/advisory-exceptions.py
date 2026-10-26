#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
"""The accepted security advisories: the `[advisories] ignore` list of deny.toml.

Usage:
    advisory-exceptions.py check [deny.toml]       validate the list and print it
    advisory-exceptions.py audit-args [deny.toml]  validate, then print one `--ignore <id>` pair
                                                   per line, for cargo audit

Every entry must be a table with the advisory `id` and a `reason` that says why the advisory does
not make the CLI exploitable and ends with `Review by YYYY-MM-DD.`, a date that has not passed.
A bare id, a missing reason, a missing or past review date is an error, so an advisory cannot be
accepted without a written reason, and an acceptance lapses unless it is reviewed (CONTRIBUTING.md,
"Known vulnerabilities at release"). cargo deny reads the same list; cargo audit gets it from here,
so both tools accept exactly the same advisories.

Exit status: 0 when the list is valid (possibly empty), 1 otherwise.
"""

import datetime
import pathlib
import re
import sys
import tomllib

ID = re.compile(r"^(RUSTSEC-\d{4}-\d{4}|GHSA(-[23456789cfghjmpqrvwx]{4}){3})$")
REVIEW = re.compile(r"Review by (\d{4}-\d{2}-\d{2})\.\s*$")


def entries(text, today):
    """Returns the accepted advisories as (id, reason, review date), or raises ValueError."""
    config = tomllib.loads(text)
    ignore = config.get("advisories", {}).get("ignore", [])
    if not isinstance(ignore, list):
        raise ValueError("[advisories] ignore is not a list")
    out = []
    problems = []
    for n, entry in enumerate(ignore, 1):
        where = f"[advisories] ignore, entry {n}"
        if not isinstance(entry, dict):
            problems.append(f"{where}: {entry!r} has no reason; write {{ id = ..., reason = ... }}")
            continue
        advisory = entry.get("id")
        reason = entry.get("reason")
        if not isinstance(advisory, str) or not ID.match(advisory):
            problems.append(f"{where}: no advisory id (RUSTSEC-YYYY-NNNN or GHSA-...)")
            continue
        if not isinstance(reason, str) or not reason.strip():
            problems.append(f"{where}: {advisory} has no reason")
            continue
        match = REVIEW.search(reason)
        if not match:
            problems.append(f"{where}: the reason of {advisory} does not end with 'Review by YYYY-MM-DD.'")
            continue
        try:
            review = datetime.date.fromisoformat(match.group(1))
        except ValueError:
            problems.append(f"{where}: {advisory} has an invalid review date {match.group(1)}")
            continue
        if review < today:
            problems.append(f"{where}: the acceptance of {advisory} lapsed on {review}; review it")
            continue
        out.append((advisory, reason.strip(), review))
    if problems:
        raise ValueError("\n".join(problems))
    return out


def main(argv):
    if len(argv) not in (2, 3) or argv[1] not in ("check", "audit-args"):
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    path = pathlib.Path(argv[2] if len(argv) == 3 else "deny.toml")
    try:
        accepted = entries(path.read_text(), datetime.date.today())
    except (OSError, tomllib.TOMLDecodeError, ValueError) as error:
        print(f"advisory-exceptions.py: {path}: {error}", file=sys.stderr)
        return 1
    if argv[1] == "audit-args":
        for advisory, _, _ in accepted:
            print("--ignore")
            print(advisory)
        return 0
    if not accepted:
        print("No accepted advisories.")
    for advisory, reason, review in accepted:
        print(f"{advisory} (review by {review}): {reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
