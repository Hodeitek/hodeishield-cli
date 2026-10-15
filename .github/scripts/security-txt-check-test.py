#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
"""Tests of security-txt-check.py, including the published .well-known/security.txt.

Usage: python3 -I .github/scripts/security-txt-check-test.py

Tests whose names contain "negative" feed changed data on purpose; they run in CI.
"""

import datetime
import importlib.util
import pathlib
import unittest

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("security_txt_check", HERE / "security-txt-check.py")
sc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sc)

NOW = datetime.datetime(2026, 10, 15, tzinfo=datetime.timezone.utc)
GOOD = """# A comment
Contact: mailto:security@example.com
Contact: https://example.com/report
Expires: 2027-09-15T00:00:00.000Z
Preferred-Languages: en, es
Policy: https://example.com/policy
Canonical: https://example.com/.well-known/security.txt
"""


def without(prefix):
    return "".join(line for line in GOOD.splitlines(True) if not line.startswith(prefix))


def problems(text, now=NOW):
    return sc.check(text, now)[0]


class SecurityTxtCheck(unittest.TestCase):
    def test_good_file_passes(self):
        found, days = sc.check(GOOD, NOW)
        self.assertEqual(found, [])
        self.assertEqual(days, 335)

    def test_published_file_is_valid(self):
        # Checked as of 90 days before it expires, so this test does not turn red when the expiry
        # approaches; the weekly check in security-txt.yml does that.
        text = (HERE.parent.parent / ".well-known" / "security.txt").read_text(encoding="utf-8")
        fields, _ = sc.parse(text)
        as_of = sc.parse_expires(fields["expires"][0]) - datetime.timedelta(days=90)
        self.assertEqual(problems(text, as_of), [])

    def test_published_file_names_this_repository(self):
        text = (HERE.parent.parent / ".well-known" / "security.txt").read_text(encoding="utf-8")
        fields, _ = sc.parse(text)
        self.assertIn("mailto:security@hodeitek.com", fields["contact"])
        self.assertTrue(fields["policy"][0].endswith("/Hodeitek/hodeishield-cli/blob/main/SECURITY.md"))

    def test_negative_missing_contact(self):
        self.assertIn("Contact is missing", problems(without("Contact:")))

    def test_negative_missing_expires(self):
        self.assertIn("Expires is missing", problems(without("Expires:")))

    def test_negative_expired(self):
        later = datetime.datetime(2027, 9, 16, tzinfo=datetime.timezone.utc)
        self.assertTrue(any("expired" in p for p in problems(GOOD, later)))

    def test_negative_expiring_soon(self):
        soon = datetime.datetime(2027, 7, 20, tzinfo=datetime.timezone.utc)
        self.assertTrue(any("renew it" in p for p in problems(GOOD, soon)))

    def test_threshold_is_sixty_days(self):
        edge = datetime.datetime(2027, 7, 17, tzinfo=datetime.timezone.utc)  # exactly 60 days left
        self.assertEqual(problems(GOOD, edge), [])
        before = datetime.datetime(2027, 7, 18, tzinfo=datetime.timezone.utc)  # 59 days left
        self.assertTrue(any("renew it" in p for p in problems(GOOD, before)))

    def test_negative_too_far_ahead(self):
        text = GOOD.replace("2027-09-15", "2028-01-01")
        self.assertTrue(any("more than a year" in p for p in problems(text)))

    def test_negative_expires_without_time_zone(self):
        text = GOOD.replace("2027-09-15T00:00:00.000Z", "2027-09-15T00:00:00")
        self.assertTrue(any("time zone" in p for p in problems(text)))

    def test_negative_expires_not_a_date(self):
        text = GOOD.replace("2027-09-15T00:00:00.000Z", "next year")
        self.assertTrue(any("Expires is not" in p for p in problems(text)))

    def test_negative_expires_twice(self):
        self.assertIn("expires must appear only once", problems(GOOD + "Expires: 2027-09-15T00:00:00Z\n"))

    def test_negative_plain_http_urls(self):
        self.assertTrue(any("policy" in p for p in problems(GOOD.replace("https://example.com/policy", "http://example.com/policy"))))
        text = GOOD.replace("https://example.com/.well-known", "http://example.com/.well-known")
        self.assertTrue(any("canonical" in p for p in problems(text)))

    def test_negative_bad_contact(self):
        self.assertTrue(any("Contact must be" in p for p in problems(GOOD + "Contact: security@example.com\n")))
        self.assertTrue(any("Contact must be" in p for p in problems(GOOD + "Contact: http://example.com\n")))

    def test_negative_bad_language(self):
        text = GOOD.replace("en, es", "english; spanish")
        self.assertTrue(any("Preferred-Languages" in p for p in problems(text)))

    def test_negative_not_a_field(self):
        self.assertTrue(any("not a field" in p for p in problems(GOOD + "this is not a field\n")))

    def test_negative_unknown_field(self):
        self.assertIn("unknown field secret", problems(GOOD + "Secret: x\n"))

    def test_extension_fields_are_allowed(self):
        self.assertEqual(problems(GOOD + "X-Note: ok\n"), [])


if __name__ == "__main__":
    unittest.main()
