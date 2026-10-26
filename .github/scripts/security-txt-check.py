#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
"""Checks .well-known/security.txt against RFC 9116 and reminds the maintainers to renew it.

Usage: python3 -I .github/scripts/security-txt-check.py [FILE] [--warn-days N] [--today YYYY-MM-DD]

Fails (exit 1) when the file breaks a requirement of RFC 9116 that matters here, when it has
expired, or when fewer than --warn-days (default 60) days remain before its Expires date. Prints
one line per problem and, when all is well, how many days remain. Reads the file only.
"""

import argparse
import datetime
import re
import sys

DEFAULT_FILE = ".well-known/security.txt"
DEFAULT_WARN_DAYS = 60
# Fields that may appear once (RFC 9116, section 2.5).
SINGLE = {"expires", "preferred-languages", "canonical", "policy", "hiring", "csaf"}
KNOWN = SINGLE | {"contact", "encryption", "acknowledgments"}
# RFC 5646 language tags, simplified: letters, then optional subtags.
LANGUAGE = re.compile(r"^[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8})*$")


def parse(text):
    """Returns (fields, problems): fields maps a lower-case name to its list of values."""
    fields, problems = {}, []
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("-----BEGIN PGP"):
            problems.append(f"line {number}: a signed file is not expected here")
            continue
        name, sep, value = line.partition(":")
        if not sep or not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*", name):
            problems.append(f"line {number}: not a field or a comment")
            continue
        fields.setdefault(name.lower(), []).append(value.strip())
    return fields, problems


def parse_expires(value):
    """An ISO 8601 date and time with a time zone, as RFC 9116 requires. Raises ValueError."""
    if not re.search(r"(Z|[+-]\d{2}:\d{2})$", value):
        raise ValueError("no time zone")
    when = datetime.datetime.fromisoformat(value)
    if when.tzinfo is None:
        raise ValueError("no time zone")
    return when


def check(text, now, warn_days=DEFAULT_WARN_DAYS):
    """Returns (problems, days_left). days_left is None when Expires cannot be read."""
    fields, problems = parse(text)
    for name in sorted(fields):
        if name not in KNOWN and not name.startswith("x-"):
            problems.append(f"unknown field {name}")
        if name in SINGLE and len(fields[name]) > 1:
            problems.append(f"{name} must appear only once")

    contacts = fields.get("contact", [])
    if not contacts:
        problems.append("Contact is missing")
    for value in contacts:
        if not re.match(r"(https://\S+|mailto:[^@\s]+@[^@\s]+|tel:\+?[0-9 .()-]+)$", value):
            problems.append(f"Contact must be an https:, mailto: or tel: URI: {value!r}")

    for name in ("policy", "canonical", "encryption", "acknowledgments", "hiring", "csaf"):
        for value in fields.get(name, []):
            if not re.match(r"https://\S+$", value):
                problems.append(f"{name} must be an https: URL: {value!r}")

    for value in fields.get("preferred-languages", []):
        tags = [tag.strip() for tag in value.split(",")]
        if not all(LANGUAGE.match(tag) for tag in tags):
            problems.append(f"Preferred-Languages is not a list of language tags: {value!r}")

    days_left = None
    expires = fields.get("expires", [])
    if not expires:
        problems.append("Expires is missing")
    elif len(expires) == 1:
        try:
            when = parse_expires(expires[0])
        except ValueError as error:
            problems.append(f"Expires is not an ISO 8601 date and time with a time zone ({error}): {expires[0]!r}")
        else:
            delta = when - now
            days_left = delta.days
            if delta <= datetime.timedelta(0):
                problems.append(f"the file expired on {expires[0]}")
            elif delta > datetime.timedelta(days=366):
                problems.append("Expires is more than a year ahead; RFC 9116 recommends less than a year")
            elif delta < datetime.timedelta(days=warn_days):
                problems.append(
                    f"the file expires on {expires[0]}, in {days_left} days (less than {warn_days}); renew it"
                )
    return problems, days_left


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("file", nargs="?", default=DEFAULT_FILE)
    parser.add_argument("--warn-days", type=int, default=DEFAULT_WARN_DAYS)
    parser.add_argument("--today", help="UTC date to check against, for tests (default: now)")
    args = parser.parse_args(argv)
    if args.today:
        now = datetime.datetime.fromisoformat(args.today).replace(tzinfo=datetime.timezone.utc)
    else:
        now = datetime.datetime.now(datetime.timezone.utc)
    try:
        with open(args.file, encoding="utf-8") as handle:
            text = handle.read()
    except OSError as error:
        print(f"{args.file}: cannot be read: {error}")
        return 1
    problems, days_left = check(text, now, args.warn_days)
    for problem in problems:
        print(f"{args.file}: {problem}")
    if problems:
        return 1
    print(f"{args.file}: valid, expires in {days_left} days")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
