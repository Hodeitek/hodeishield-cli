#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
"""Tests of advisory-exceptions.py.

Usage: python3 -I .github/scripts/advisory-exceptions-test.py

Tests whose names contain "negative" feed lists that must be refused; they run in CI.
"""

import datetime
import importlib.util
import pathlib
import unittest

spec = importlib.util.spec_from_file_location(
    "advisory_exceptions", pathlib.Path(__file__).with_name("advisory-exceptions.py")
)
ae = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ae)

TODAY = datetime.date(2026, 10, 13)


def deny(ignore):
    return f"[advisories]\nignore = [\n{ignore}\n]\n"


class Accepted(unittest.TestCase):
    def test_empty_list(self):
        self.assertEqual(ae.entries(deny(""), TODAY), [])

    def test_no_advisories_section(self):
        self.assertEqual(ae.entries("[licenses]\nallow = []\n", TODAY), [])

    def test_the_repository_deny_toml_is_valid(self):
        text = (pathlib.Path(__file__).parents[2] / "deny.toml").read_text()
        ae.entries(text, datetime.date.today())

    def test_entry_with_reason_and_review_date(self):
        got = ae.entries(
            deny('{ id = "RUSTSEC-2026-0001", reason = "Only reached from tests. Review by 2027-01-31." },'),
            TODAY,
        )
        self.assertEqual(got, [("RUSTSEC-2026-0001", "Only reached from tests. Review by 2027-01-31.",
                                datetime.date(2027, 1, 31))])

    def test_review_today_is_still_valid(self):
        ae.entries(deny('{ id = "RUSTSEC-2026-0001", reason = "Why. Review by 2026-10-13." },'), TODAY)

    def test_ghsa_id(self):
        got = ae.entries(deny('{ id = "GHSA-2v3w-4x5c-6f7g", reason = "Why. Review by 2027-01-31." },'), TODAY)
        self.assertEqual(got[0][0], "GHSA-2v3w-4x5c-6f7g")


class Refused(unittest.TestCase):
    def refused(self, ignore, words):
        with self.assertRaises(ValueError) as caught:
            ae.entries(deny(ignore), TODAY)
        self.assertIn(words, str(caught.exception))

    def test_negative_bare_id(self):
        self.refused('"RUSTSEC-2026-0001",', "has no reason")

    def test_negative_missing_reason(self):
        self.refused('{ id = "RUSTSEC-2026-0001" },', "has no reason")

    def test_negative_empty_reason(self):
        self.refused('{ id = "RUSTSEC-2026-0001", reason = "  " },', "has no reason")

    def test_negative_no_review_date(self):
        self.refused('{ id = "RUSTSEC-2026-0001", reason = "Not reachable." },', "does not end with")

    def test_negative_review_date_not_at_the_end(self):
        self.refused('{ id = "RUSTSEC-2026-0001", reason = "Review by 2027-01-31. Later text." },',
                     "does not end with")

    def test_negative_lapsed_review_date(self):
        self.refused('{ id = "RUSTSEC-2026-0001", reason = "Why. Review by 2026-10-12." },', "lapsed")

    def test_negative_invalid_review_date(self):
        self.refused('{ id = "RUSTSEC-2026-0001", reason = "Why. Review by 2027-02-30." },', "invalid review date")

    def test_negative_bad_id(self):
        self.refused('{ id = "CVE-2026-0001", reason = "Why. Review by 2027-01-31." },', "no advisory id")

    def test_negative_every_problem_is_reported(self):
        with self.assertRaises(ValueError) as caught:
            ae.entries(deny('"RUSTSEC-2026-0001",\n{ id = "RUSTSEC-2026-0002", reason = "Why." },'), TODAY)
        self.assertIn("entry 1", str(caught.exception))
        self.assertIn("entry 2", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
