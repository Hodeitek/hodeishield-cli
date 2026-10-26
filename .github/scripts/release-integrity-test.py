#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
"""Tests of release-integrity.py that need no network: certificate parsing and the matching rules.

Usage: python3 .github/scripts/release-integrity-test.py

Tests whose names contain "negative" feed changed data on purpose; they run in CI.
"""

import importlib.util
import json
import pathlib
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "release_integrity", pathlib.Path(__file__).with_name("release-integrity.py")
)
ri = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ri)

REPO = "Hodeitek/hodeishield-cli"
COMMIT_041 = "b90bb412c45df7318e1300dfdb04f80e87ab77f5"
RUN_041 = 38235963722

# The certificate of the Rekor entry for SHA256SUMS of v0.4.1 (log index 3226122241), public data.
CERT_041 = b"""-----BEGIN CERTIFICATE-----
MIIHDzCCBpagAwIBAgIUWE8VP/HNaszjJPJvW74SgHLvfucwCgYIKoZIzj0EAwMw
NzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRl
cm1lZGlhdGUwHhcNMjYxMDEyMTAzMTU4WhcNMjYxMDEyMTA0MTU4WjAAMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAEMqNSAObLo6cpTWUTKgPZip2AmZutq/BdQ7EI
GFM3ThzIef8qNB0zf9IVoQg7pXDetns1X/Gvvv6I50QWhd2ZJqOCBbUwggWxMA4G
A1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAfBgNVHSMEGDAWgBTf
0+nPViQRlvmo2OkoVaLGLhhkPzBoBgNVHREBAf8EXjBchlpodHRwczovL2dpdGh1
Yi5jb20vSG9kZWl0ZWsvaG9kZWlzaGllbGQtY2xpLy5naXRodWIvd29ya2Zsb3dz
L3JlbGVhc2UueW1sQHJlZnMvdGFncy92MC40LjEwOQYKKwYBBAGDvzABAQQraHR0
cHM6Ly90b2tlbi5hY3Rpb25zLmdpdGh1YnVzZXJjb250ZW50LmNvbTASBgorBgEE
AYO/MAECBARwdXNoMDYGCisGAQQBg78wAQMEKGI5MGJiNDEyYzQ1ZGY3MzE4ZTEz
MDBkZmRiMDRmODBlODdhYjc3ZjUwFQYKKwYBBAGDvzABBAQHUmVsZWFzZTAmBgor
BgEEAYO/MAEFBBhIb2RlaXRlay9ob2RlaXNoaWVsZC1jbGkwHgYKKwYBBAGDvzAB
BgQQcmVmcy90YWdzL3YwLjQuMTA7BgorBgEEAYO/MAEIBC0MK2h0dHBzOi8vdG9r
ZW4uYWN0aW9ucy5naXRodWJ1c2VyY29udGVudC5jb20wagYKKwYBBAGDvzABCQRc
DFpodHRwczovL2dpdGh1Yi5jb20vSG9kZWl0ZWsvaG9kZWlzaGllbGQtY2xpLy5n
aXRodWIvd29ya2Zsb3dzL3JlbGVhc2UueW1sQHJlZnMvdGFncy92MC40LjEwOAYK
KwYBBAGDvzABCgQqDChiOTBiYjQxMmM0NWRmNzMxOGUxMzAwZGZkYjA0ZjgwZTg3
YWI3N2Y1MB0GCisGAQQBg78wAQsEDwwNZ2l0aHViLWhvc3RlZDA7BgorBgEEAYO/
MAEMBC0MK2h0dHBzOi8vZ2l0aHViLmNvbS9Ib2RlaXRlay9ob2RlaXNoaWVsZC1j
bGkwOAYKKwYBBAGDvzABDQQqDChiOTBiYjQxMmM0NWRmNzMxOGUxMzAwZGZkYjA0
ZjgwZTg3YWI3N2Y1MCAGCisGAQQBg78wAQ4EEgwQcmVmcy90YWdzL3YwLjQuMTAa
BgorBgEEAYO/MAEPBAwMCjEzOTI0OTU3NTkwKwYKKwYBBAGDvzABEAQdDBtodHRw
czovL2dpdGh1Yi5jb20vSG9kZWl0ZWswGQYKKwYBBAGDvzABEQQLDAkxNDg0Mzgz
MjgwagYKKwYBBAGDvzABEgRcDFpodHRwczovL2dpdGh1Yi5jb20vSG9kZWl0ZWsv
aG9kZWlzaGllbGQtY2xpLy5naXRodWIvd29ya2Zsb3dzL3JlbGVhc2UueW1sQHJl
ZnMvdGFncy92MC40LjEwOAYKKwYBBAGDvzABEwQqDChiOTBiYjQxMmM0NWRmNzMx
OGUxMzAwZGZkYjA0ZjgwZTg3YWI3N2Y1MBQGCisGAQQBg78wARQEBgwEcHVzaDBf
BgorBgEEAYO/MAEVBFEMT2h0dHBzOi8vZ2l0aHViLmNvbS9Ib2RlaXRlay9ob2Rl
aXNoaWVsZC1jbGkvYWN0aW9ucy9ydW5zLzM4MjM1OTYzNzIyL2F0dGVtcHRzLzEw
FgYKKwYBBAGDvzABFgQIDAZwdWJsaWMwVwYKKwYBBAGDvzABGARJDEdyZXBvOkhv
ZGVpdGVrQDE0ODQzODMyOC9ob2RlaXNoaWVsZC1jbGlAMTM5MjQ5NTc1OTpyZWY6
cmVmcy90YWdzL3YwLjQuMTCBiwYKKwYBBAHWeQIEAgR9BHsAeQB3AN09MGrGxxEy
YxkeHJlnNwKiSl643jyt/4eKcoAvKe6OAAABoS+rT98AAAQDAEgwRgIhANthYw/v
Cw9kgTo0isgfmp6O+YLofMuiq5pH5IOF0sZ+AiEAymmgynFJ5b3K625NWO6GcR2H
NzpYKdtUT9U1mxlzTOUwCgYIKoZIzj0EAwMDZwAwZAIwLpVXYbtm/e3BxGbXZooo
78R+2TfpZmEMySsqMcGmiz0o/SrBh/zyPFQ2pjIQrP3zAjBmeXHzGhn+2NiLw/l0
HRDT5K2jj/SVAV+Ew477J6XEFQbuJ93C16d7eFGa6t9LbUo=
-----END CERTIFICATE-----
"""


def certificate(tag="v0.4.1", commit=COMMIT_041, run=RUN_041, issuer=ri.ISSUER, repo=REPO):
    return {
        "san": f"https://github.com/{repo}/.github/workflows/release.yml@refs/tags/{tag}",
        "issuer": issuer,
        "commit": commit,
        "run": f"https://github.com/{repo}/actions/runs/{run}/attempts/1",
    }


RELEASES = {
    "v0.4.1": (COMMIT_041, {RUN_041}),
    "v0.4.0": ("3405f04" + "0" * 33, {38194904546}),
}


class Certificate(unittest.TestCase):
    def test_reads_the_identity_of_a_real_release_certificate(self):
        self.assertEqual(ri.identity(CERT_041), certificate())

    def test_a_truncated_certificate_is_an_error_not_an_identity(self):
        der = ri.base64.b64decode(b"".join(CERT_041.strip().splitlines()[1:-1]))
        with self.assertRaises(ValueError):
            ri.identity(der[:200])


class Rekor(unittest.TestCase):
    def judge(self, *certificates, tag="v0.4.1"):
        entries = [(index, c) for index, c in enumerate(certificates)]
        return ri.judge_rekor(entries, repository=REPO, tag=tag, releases=RELEASES)

    def test_the_release_s_own_entry_matches(self):
        self.assertEqual(self.judge(certificate()), (True, []))

    def test_no_entry_of_the_release_is_not_a_match(self):
        self.assertEqual(self.judge(), (False, []))

    def test_an_entry_of_another_published_release_is_not_a_mismatch(self):
        other = certificate("v0.4.0", RELEASES["v0.4.0"][0], 38194904546)
        self.assertEqual(self.judge(certificate(), other), (True, []))

    def test_entries_made_by_others_are_ignored(self):
        self.assertEqual(self.judge(certificate(repo="someone/else"), None), (False, []))

    def test_an_entry_with_this_identity_from_an_unknown_run_is_reported(self):
        matched, problems = self.judge(certificate(), certificate(run=1))
        self.assertTrue(matched)
        self.assertEqual(len(problems), 1)
        self.assertIn("matches no published release", problems[0])
        self.assertIn("/actions/runs/1/", problems[0])

    def test_a_tag_without_a_release_a_wrong_commit_or_issuer_is_reported(self):
        for wrong in (
            certificate(tag="v9.9.9"),
            certificate(commit="0" * 40),
            certificate(issuer="https://example.test"),
        ):
            with self.subTest(wrong=wrong):
                matched, problems = self.judge(wrong)
                self.assertFalse(matched)
                self.assertEqual(len(problems), 1)

    def test_the_identity_prefix_is_compared_without_case(self):
        matched, problems = self.judge(certificate(repo="hodeitek/HodeiShield-CLI"))
        self.assertFalse(matched)
        self.assertEqual(len(problems), 1)


FIXTURE = json.loads(pathlib.Path(__file__).with_name("release-integrity-testdata.json").read_text())


class TrustRoot(unittest.TestCase):
    def setUp(self):
        self.workdir = tempfile.TemporaryDirectory()
        self.trust = ri.Trust(FIXTURE["trusted_root"], self.workdir.name)
        self.entry = FIXTURE["entry"]
        body = json.loads(ri.base64.b64decode(self.entry["body"]))
        self.der = ri.base64.b64decode(
            b"".join(
                line
                for line in ri.base64.b64decode(body["spec"]["signature"]["publicKey"]["content"]).splitlines()
                if not line.startswith(b"-----")
            )
        )

    def tearDown(self):
        self.workdir.cleanup()

    def test_rekor_signed_the_real_entry(self):
        self.assertTrue(self.trust.timestamp_verifies(self.entry))

    def test_the_real_certificate_chains_when_it_was_logged(self):
        self.assertTrue(self.trust.certificate_chains(self.der, self.entry["integratedTime"]))

    def test_negative_a_changed_entry_is_not_signed_by_rekor(self):
        for field, value in (("integratedTime", self.entry["integratedTime"] + 1), ("logIndex", 1)):
            with self.subTest(field=field):
                self.assertFalse(self.trust.timestamp_verifies({**self.entry, field: value}))

    def test_negative_the_certificate_does_not_chain_outside_its_ten_minutes(self):
        self.assertFalse(self.trust.certificate_chains(self.der, self.entry["integratedTime"] + 3600))

    def test_negative_a_certificate_whose_signature_does_not_verify_does_not_chain(self):
        changed = self.der[:-1] + bytes([self.der[-1] ^ 1])  # the last byte of its signature
        self.assertFalse(self.trust.certificate_chains(changed, self.entry["integratedTime"]))


class Bundles(unittest.TestCase):
    SUMS = {"hodeishield-1.0.0-x86_64.tar.gz": "a" * 64, "hodeishield-1.0.0.pkg": "b" * 64}

    def test_the_required_set_ignores_which_bundles_are_attached(self):
        assets = {"SHA256SUMS", "install.sh", "hodeishield-1.0.0.msi", *self.SUMS}
        self.assertEqual(ri.must_be_signed(assets, self.SUMS), {"SHA256SUMS", "install.sh", "hodeishield-1.0.0.msi", *self.SUMS})

    def test_negative_a_deleted_bundle_does_not_shrink_the_required_set(self):
        assets = {"SHA256SUMS", "SHA256SUMS.sigstore.json", *self.SUMS}
        self.assertEqual(ri.must_be_signed(assets, self.SUMS), {"SHA256SUMS", *self.SUMS})

    def test_a_file_in_sha256sums_is_required_even_if_its_name_matches_no_pattern(self):
        self.assertIn("other.bin", ri.must_be_signed({"SHA256SUMS"}, {"other.bin": "c" * 64}))

    def test_bundles_and_provenance_are_not_required_to_have_bundles(self):
        names = {"x.tar.gz.sigstore.json", "multiple.intoto.jsonl"}
        self.assertEqual(ri.must_be_signed(names, {}), {"SHA256SUMS"})


class Parsing(unittest.TestCase):
    def test_sha256sums_in_text_and_binary_mode(self):
        text = "a" * 64 + "  one.tar.gz\n" + "b" * 64 + " *two.zip\n\n"
        self.assertEqual(
            ri.parse_sha256sums(text), {"one.tar.gz": "a" * 64, "two.zip": "b" * 64}
        )

    def test_a_line_that_is_not_a_checksum_is_unreadable(self):
        with self.assertRaises(ri.Unreadable):
            ri.parse_sha256sums("not a checksum line\n")

    def test_stable_versions_only(self):
        self.assertEqual(ri.stable_version("v0.4.1"), (0, 4, 1))
        self.assertIsNone(ri.stable_version("v0.5.0-rc.1"))
        self.assertIsNone(ri.stable_version("0.4.1"))


if __name__ == "__main__":
    unittest.main()
