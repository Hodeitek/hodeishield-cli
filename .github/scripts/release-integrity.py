#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
"""Checks that every release run, release file, Rekor entry and container image belongs together.

Usage: release-integrity.py <repository> <cosign> <trusted_root.json>

<repository> is "owner/name". <cosign> is the cosign binary used to verify the container images.
<trusted_root.json> is Sigstore's trust root as `cosign initialize` fetched and checked it through
TUF: the Fulcio certificate authorities and the Rekor public keys. GH_TOKEN, if set, is used for the
GitHub API (read-only: releases, tags, workflow runs).

What is checked, in both directions:
  runs -> releases   every run of release.yml started by a tag, and every run of container-image.yml,
                     belongs to a published release, at the commit of its tag;
  releases -> runs   every published release has a successful release.yml run for its tag at that
                     commit, and from 0.4.0 a successful container-image.yml run;
  files              every release file matches its line in the release's SHA256SUMS, and nothing
                     else is attached;
  Rekor              every file the release signs (it has a `.sigstore.json` bundle) is looked up in
                     Rekor by its SHA-256. An entry counts only if its signed entry timestamp
                     verifies with Rekor's key and its certificate chains to Sigstore's
                     certificate authority at the time it was logged: Rekor accepts any
                     certificate, so one that does not chain could claim any identity. At least
                     one entry must carry a certificate for
                     release.yml at the release's tag, from the GitHub Actions issuer, with the tag's
                     commit and a run of that tag. An entry with this repository's identity that
                     names anything else is reported. Entries made by others are ignored: anyone can
                     sign a public file;
  images             every version tag of the container image is a published release, every release
                     from 0.4.0 has one, and the signature on its digest verifies with cosign against
                     container-image.yml at that tag.

Rekor cannot be searched by certificate identity, so a signature made with the identity for a file
that was never published is not seen here (see #158).

Prints the report on standard output. Exit status: 0 when everything matches, 1 when something does
not match or cannot be read. Nothing that cannot be read is ever treated as a pass.
"""

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.github.com"
REKOR = "https://rekor.sigstore.dev"
REGISTRY = "ghcr.io"
ISSUER = "https://token.actions.githubusercontent.com"
FIRST_IMAGE = (0, 4, 0)

# Fulcio certificate extensions (https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md).
OID_SAN = "2.5.29.17"
OID_ISSUER_V1 = "1.3.6.1.4.1.57264.1.1"  # raw string
OID_COMMIT = "1.3.6.1.4.1.57264.1.3"  # raw string
OID_ISSUER = "1.3.6.1.4.1.57264.1.8"  # DER UTF8String
OID_RUN = "1.3.6.1.4.1.57264.1.21"  # DER UTF8String

# Runs that belong to no published release but are known and accepted, by run id, each with its
# reason. Keep it empty unless a reviewed pull request adds an entry.
ACCEPTED_RUNS: dict[int, str] = {}

VERSION_TAG = re.compile(r"^v(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.-]+)?$")
IMAGE_SIGNATURE_TAG = re.compile(r"^sha256-[0-9a-f]{64}(\.sig|\.att|\.sbom)?$")


class Unreadable(Exception):
    """Something the check needs could not be read."""


# --- DER, just enough to read the extensions of an X.509 certificate --------------------------


def der_items(data: bytes):
    """Yields (tag, content) for each TLV at the top level of `data`."""
    i = 0
    while i < len(data):
        tag = data[i]
        i += 1
        if i >= len(data):
            raise ValueError("truncated DER")
        length = data[i]
        i += 1
        if length & 0x80:
            count = length & 0x7F
            if count == 0 or count > 4 or i + count > len(data):
                raise ValueError("bad DER length")
            length = int.from_bytes(data[i : i + count], "big")
            i += count
        if i + length > len(data):
            raise ValueError("truncated DER")
        yield tag, data[i : i + length]
        i += length


def der_oid(content: bytes) -> str:
    first = content[0]
    parts = [str(min(first // 40, 2)), str(first - 40 * min(first // 40, 2))]
    value = 0
    for byte in content[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


def certificate_extensions(der: bytes) -> dict[str, bytes]:
    """The extensions of a certificate, as OID -> extension value (the OCTET STRING's content)."""
    ((tag, certificate),) = der_items(der)
    if tag != 0x30:
        raise ValueError("not a certificate")
    tbs = next(der_items(certificate))[1]
    for tag, content in der_items(tbs):
        if tag == 0xA3:  # [3] extensions
            extensions = next(der_items(content))[1]
            found = {}
            for _, extension in der_items(extensions):
                parts = list(der_items(extension))
                oid = der_oid(parts[0][1])
                found[oid] = parts[-1][1]  # skips the optional `critical` BOOLEAN
            return found
    return {}


def der_text(value: bytes) -> str:
    """A Fulcio extension value: a DER UTF8String (newer OIDs) or the raw text (1.1 to 1.6)."""
    if value[:1] == b"\x0c":
        ((_, text),) = der_items(value)
        return text.decode()
    return value.decode()


def san_uris(value: bytes) -> list[str]:
    ((_, names),) = der_items(value)
    return [content.decode() for tag, content in der_items(names) if tag == 0x86]


def identity(pem_or_der: bytes) -> dict[str, str]:
    """The signer identity a Fulcio certificate states."""
    der = pem_or_der
    if pem_or_der.lstrip().startswith(b"-----BEGIN"):
        body = b"".join(
            line for line in pem_or_der.strip().splitlines() if not line.startswith(b"-----")
        )
        der = base64.b64decode(body)
    extensions = certificate_extensions(der)
    issuer = extensions.get(OID_ISSUER) or extensions.get(OID_ISSUER_V1)
    return {
        "san": ", ".join(san_uris(extensions[OID_SAN])) if OID_SAN in extensions else "",
        "issuer": der_text(issuer) if issuer else "",
        "commit": der_text(extensions[OID_COMMIT]) if OID_COMMIT in extensions else "",
        "run": der_text(extensions[OID_RUN]) if OID_RUN in extensions else "",
    }


# --- HTTP ---------------------------------------------------------------------------------------


def http(url: str, *, data=None, headers=None, method=None, token=None):
    """Returns (status, headers, body). Retries rate limits and server errors a few times."""
    headers = dict(headers or {})
    headers.setdefault("User-Agent", "hodeishield-release-integrity")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    for attempt in range(4):
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.status, response.headers, response.read()
        except urllib.error.HTTPError as error:
            if error.code in (429, 500, 502, 503, 504) and attempt < 3:
                time.sleep(2 ** (attempt + 1))
                continue
            return error.code, error.headers, error.read()
        except urllib.error.URLError as error:
            if attempt < 3:
                time.sleep(2 ** (attempt + 1))
                continue
            raise Unreadable(f"{url}: {error.reason}") from error
    raise AssertionError("unreachable")


class GitHub:
    def __init__(self, repository: str, token: str | None):
        self.repository = repository
        self.token = token

    def get(self, path: str):
        status, _, body = http(
            f"{API}/repos/{self.repository}/{path}",
            headers={"Accept": "application/vnd.github+json"},
            token=self.token,
        )
        if status != 200:
            raise Unreadable(f"GET {path}: HTTP {status}")
        return json.loads(body)

    def pages(self, path: str, key: str | None = None):
        items, page = [], 1
        separator = "&" if "?" in path else "?"
        while True:
            data = self.get(f"{path}{separator}per_page=100&page={page}")
            batch = data[key] if key else data
            items.extend(batch)
            if len(batch) < 100:
                return items
            page += 1

    def tag_commit(self, tag: str) -> str:
        ref = self.get(f"git/ref/tags/{urllib.parse.quote(tag)}")["object"]
        while ref["type"] == "tag":
            ref = self.get(f"git/tags/{ref['sha']}")["object"]
        if ref["type"] != "commit":
            raise Unreadable(f"tag {tag} points to a {ref['type']}")
        return ref["sha"]


def download(url: str) -> bytes:
    status, _, body = http(url)
    if status != 200:
        raise Unreadable(f"{url}: HTTP {status}")
    return body


def parse_sha256sums(text: str) -> dict[str, str]:
    sums = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r"([0-9a-f]{64}) [ *](\S+)", line)
        if not match:
            raise Unreadable(f"SHA256SUMS line not understood: {line!r}")
        sums[match.group(2)] = match.group(1)
    return sums


# --- Sigstore's trust root ----------------------------------------------------------------------


def pem(der: bytes, label: str = "CERTIFICATE") -> str:
    body = "\n".join(textwrap.wrap(base64.b64encode(der).decode(), 64))
    return f"-----BEGIN {label}-----\n{body}\n-----END {label}-----\n"


class Trust:
    """Checks a Rekor entry against Sigstore's trust root, with openssl."""

    def __init__(self, trusted_root: dict, workdir: str):
        self.workdir = workdir
        roots, intermediates = [], []
        for authority in trusted_root.get("certificateAuthorities", []):
            chain = [base64.b64decode(c["rawBytes"]) for c in authority["certChain"]["certificates"]]
            roots.append(pem(chain[-1]))
            intermediates.extend(pem(der) for der in chain[:-1])
        if not roots:
            raise Unreadable("the trust root lists no certificate authority")
        self.roots = self._write("roots.pem", "".join(roots))
        self.intermediates = (
            self._write("intermediates.pem", "".join(intermediates)) if intermediates else None
        )
        self.rekor_keys = {}
        for log in trusted_root.get("tlogs", []):
            if log.get("baseUrl", "").rstrip("/") == REKOR:
                log_id = base64.b64decode(log["logId"]["keyId"]).hex()
                self.rekor_keys[log_id] = self._write(
                    f"rekor-{log_id}.pem", pem(base64.b64decode(log["publicKey"]["rawBytes"]), "PUBLIC KEY")
                )
        if not self.rekor_keys:
            raise Unreadable(f"the trust root has no key for {REKOR}")

    def _write(self, name: str, content) -> str:
        path = f"{self.workdir}/{name}"
        with open(path, "wb" if isinstance(content, bytes) else "w") as file:
            file.write(content)
        return path

    def timestamp_verifies(self, entry: dict) -> bool:
        """Whether Rekor signed this entry, its log index and the time it was logged."""
        key = self.rekor_keys.get(entry.get("logID", ""))
        signature = entry.get("verification", {}).get("signedEntryTimestamp")
        if not key or not signature:
            return False
        payload = json.dumps(
            {
                "body": entry["body"],
                "integratedTime": entry["integratedTime"],
                "logID": entry["logID"],
                "logIndex": entry["logIndex"],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        payload_path = self._write("set-payload", payload.encode())
        signature_path = self._write("set-signature", base64.b64decode(signature))
        result = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", key, "-signature", signature_path, payload_path],
            capture_output=True,
            check=False,
        )
        return result.returncode == 0

    def certificate_chains(self, der: bytes, when: int) -> bool:
        """Whether a certificate was issued by Sigstore's certificate authority and valid at `when`."""
        leaf = self._write("leaf.pem", pem(der))
        command = ["openssl", "verify", "-attime", str(when), "-CAfile", self.roots]
        if self.intermediates:
            command += ["-untrusted", self.intermediates]
        result = subprocess.run([*command, leaf], capture_output=True, check=False)
        return result.returncode == 0


# --- Rekor --------------------------------------------------------------------------------------


def rekor_entries(digest: str, trust: Trust):
    """The Rekor entries for an artifact SHA-256, as (log index, certificate identity or None).

    The identity is None for an entry that is not a certificate signature, whose timestamp Rekor did
    not sign, or whose certificate Sigstore's certificate authority did not issue: such an entry can
    claim any identity, so it says nothing about who signed.
    """
    status, _, body = http(
        f"{REKOR}/api/v1/index/retrieve",
        data=json.dumps({"hash": f"sha256:{digest}"}).encode(),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    if status != 200:
        raise Unreadable(f"Rekor index lookup for {digest}: HTTP {status}")
    entries = []
    for uuid in json.loads(body):
        status, _, body = http(f"{REKOR}/api/v1/log/entries/{uuid}")
        if status != 200:
            raise Unreadable(f"Rekor entry {uuid}: HTTP {status}")
        entry = next(iter(json.loads(body).values()))
        spec = json.loads(base64.b64decode(entry["body"]))
        certificate = None
        if spec.get("kind") == "hashedrekord":
            content = spec["spec"]["signature"].get("publicKey", {}).get("content")
            if content:
                try:
                    der = base64.b64decode(content)
                    if der.lstrip().startswith(b"-----BEGIN"):
                        der = base64.b64decode(
                            b"".join(l for l in der.strip().splitlines() if not l.startswith(b"-----"))
                        )
                    claimed = identity(der)
                except (ValueError, KeyError, StopIteration, UnicodeDecodeError):
                    claimed = None  # a public key, not a certificate: not this workflow's
                if claimed and trust.timestamp_verifies(entry) and trust.certificate_chains(
                    der, entry["integratedTime"]
                ):
                    certificate = claimed
        entries.append((entry["logIndex"], certificate))
    return entries


def signed_by(certificate, *, repository, tag, commit, run_ids) -> bool:
    """Whether a certificate is release.yml's at `tag`, from the GitHub Actions issuer, at `commit`,
    in one of `run_ids`."""
    run = re.search(r"/actions/runs/(\d+)/", certificate["run"])
    return (
        certificate["san"] == f"https://github.com/{repository}/.github/workflows/release.yml@refs/tags/{tag}"
        and certificate["issuer"] == ISSUER
        and certificate["commit"] == commit
        and bool(run)
        and int(run.group(1)) in run_ids
    )


def judge_rekor(entries, *, repository, tag, releases) -> tuple[bool, list[str]]:
    """Whether an entry was made by the release `tag`, and every entry with this repository's
    identity that no published release made.

    `releases` maps each published tag to (commit, ids of its successful release.yml runs). A file
    that two releases ship unchanged (install.sh, for one) is signed by both, so an entry of another
    published release is not a mismatch.
    """
    prefix = f"https://github.com/{repository}/".lower()
    matched, problems = False, []
    for log_index, certificate in entries:
        if not certificate or not certificate["san"].lower().startswith(prefix):
            continue
        made_by = [
            other
            for other, (commit, run_ids) in releases.items()
            if signed_by(certificate, repository=repository, tag=other, commit=commit, run_ids=run_ids)
        ]
        if tag in made_by:
            matched = True
        elif not made_by:
            problems.append(
                f"Rekor log index {log_index} matches no published release: identity "
                f"{certificate['san']}, issuer {certificate['issuer'] or 'missing'}, commit "
                f"{certificate['commit'] or 'missing'}, run {certificate['run'] or 'missing'}"
            )
    return matched, problems


# --- Container images ---------------------------------------------------------------------------


def registry_token(image: str) -> str:
    status, _, body = http(f"https://{REGISTRY}/token?scope=repository:{image}:pull")
    if status != 200:
        raise Unreadable(f"anonymous registry token: HTTP {status}")
    return json.loads(body)["token"]


def image_tags(image: str, token: str) -> list[str]:
    tags, url = [], f"https://{REGISTRY}/v2/{image}/tags/list?n=1000"
    while url:
        status, headers, body = http(url, token=token)
        if status != 200:
            raise Unreadable(f"tags of {image}: HTTP {status}")
        tags.extend(json.loads(body).get("tags") or [])
        link = re.search(r"<([^>]+)>;\s*rel=\"next\"", headers.get("Link", ""))
        url = urllib.parse.urljoin(f"https://{REGISTRY}", link.group(1)) if link else None
    return tags


def image_digest(image: str, tag: str, token: str) -> str:
    accept = ", ".join(
        [
            "application/vnd.oci.image.index.v1+json",
            "application/vnd.docker.distribution.manifest.list.v2+json",
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.v2+json",
        ]
    )
    status, headers, _ = http(
        f"https://{REGISTRY}/v2/{image}/manifests/{tag}",
        headers={"Accept": accept},
        method="HEAD",
        token=token,
    )
    digest = headers.get("Docker-Content-Digest", "") if status == 200 else ""
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise Unreadable(f"digest of {image}:{tag}: HTTP {status}")
    return digest


def cosign_verifies(cosign: str, reference: str, identity_uri: str) -> tuple[bool, str]:
    result = subprocess.run(
        [
            cosign,
            "verify",
            reference,
            "--certificate-identity",
            identity_uri,
            "--certificate-oidc-issuer",
            ISSUER,
            "--certificate-github-workflow-trigger",
            "release",
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    return result.returncode == 0, (result.stderr.strip().splitlines() or [""])[-1]


# --- The check ----------------------------------------------------------------------------------


def stable_version(tag: str):
    """(major, minor, patch) of a stable release tag such as v0.4.1; None for anything else."""
    match = VERSION_TAG.match(tag)
    if not match or match.group(4):
        return None
    return tuple(int(part) for part in match.groups()[:3])


def check(repository: str, cosign: str, trust: Trust, github: GitHub, out) -> bool:
    problems: list[str] = []

    def problem(text: str):
        problems.append(text)
        print(f"MISMATCH: {text}", file=out)

    releases = [r for r in github.pages("releases") if not r["draft"]]
    print(f"{len(releases)} published releases.", file=out)
    commits = {r["tag_name"]: github.tag_commit(r["tag_name"]) for r in releases}

    release_runs = github.pages("actions/workflows/release.yml/runs", "workflow_runs")
    image_runs = github.pages("actions/workflows/container-image.yml/runs", "workflow_runs")
    print(
        f"{len(release_runs)} runs of release.yml, {len(image_runs)} of container-image.yml.",
        file=out,
    )

    # runs -> releases
    for run in release_runs:
        if run["event"] == "workflow_dispatch":
            continue  # a manual run is always a dry run: it signs and publishes nothing
        where = f"release.yml run {run['id']} ({run['event']}, {run['head_branch']}, {run['conclusion']})"
        if run["id"] in ACCEPTED_RUNS:
            print(f"accepted: {where}: {ACCEPTED_RUNS[run['id']]}", file=out)
        elif run["event"] != "push":
            problem(f"{where}: unexpected event")
        elif run["head_branch"] not in commits:
            problem(f"{where}: no published release has this tag")
        elif run["head_sha"] != commits[run["head_branch"]]:
            problem(f"{where}: commit {run['head_sha']} is not the tag's {commits[run['head_branch']]}")
    for run in image_runs:
        where = f"container-image.yml run {run['id']} ({run['event']}, {run['head_branch']}, {run['conclusion']})"
        if run["id"] in ACCEPTED_RUNS:
            print(f"accepted: {where}: {ACCEPTED_RUNS[run['id']]}", file=out)
        elif run["event"] != "release":
            problem(f"{where}: unexpected event")
        elif run["head_branch"] not in commits:
            problem(f"{where}: no published release has this tag")
        elif run["head_sha"] != commits[run["head_branch"]]:
            problem(f"{where}: commit {run['head_sha']} is not the tag's {commits[run['head_branch']]}")

    image = repository.lower()
    token = registry_token(image)
    tags = image_tags(image, token)

    # Each published tag, its commit and its successful release.yml runs.
    signers = {
        tag: (
            commit,
            {
                run["id"]
                for run in release_runs
                if run["event"] == "push"
                and run["head_branch"] == tag
                and run["head_sha"] == commit
                and run["conclusion"] == "success"
            },
        )
        for tag, commit in commits.items()
    }

    # releases -> runs, files, Rekor, image
    for release in releases:
        tag, commit = release["tag_name"], commits[release["tag_name"]]
        version = stable_version(tag)
        if not signers[tag][1]:
            problem(f"{tag}: no successful release.yml run for the tag at {commit}")

        assets = {asset["name"]: asset for asset in release["assets"]}
        if "SHA256SUMS" not in assets:
            problem(f"{tag}: no SHA256SUMS")
            continue
        sums_bytes = download(assets["SHA256SUMS"]["browser_download_url"])
        sums = parse_sha256sums(sums_bytes.decode())
        digests = {"SHA256SUMS": hashlib.sha256(sums_bytes).hexdigest()}
        for name, expected in sums.items():
            asset = assets.get(name)
            if not asset:
                problem(f"{tag}: {name} is in SHA256SUMS but not attached")
                continue
            digest = (asset.get("digest") or "").removeprefix("sha256:")
            if not digest:
                digest = hashlib.sha256(download(asset["browser_download_url"])).hexdigest()
            digests[name] = digest
            if digest != expected:
                problem(f"{tag}: {name} has SHA-256 {digest}, SHA256SUMS says {expected}")
        for name in assets:
            if name not in sums and name != "SHA256SUMS" and not name.endswith(
                (".sigstore.json", ".intoto.jsonl")
            ):
                problem(f"{tag}: {name} is attached but not in SHA256SUMS")

        signed = [name for name in digests if f"{name}.sigstore.json" in assets]
        if not signed:
            problem(f"{tag}: no file has a Sigstore bundle")
        for name in signed:
            matched, wrong = judge_rekor(
                rekor_entries(digests[name], trust), repository=repository, tag=tag, releases=signers
            )
            for text in wrong:
                problem(f"{tag}: {name} (sha256:{digests[name]}): {text}")
            if not matched:
                problem(
                    f"{tag}: {name} (sha256:{digests[name]}): no Rekor entry from release.yml at "
                    f"this tag, commit and run"
                )
        print(f"{tag}: {len(sums)} files, {len(signed)} signed, checked.", file=out)

        if version and version >= FIRST_IMAGE:
            image_tag = tag[1:]
            if not any(
                run["event"] == "release"
                and run["head_branch"] == tag
                and run["head_sha"] == commit
                and run["conclusion"] == "success"
                for run in image_runs
            ):
                problem(f"{tag}: no successful container-image.yml run")
            if image_tag not in tags:
                problem(f"{tag}: the container image has no tag {image_tag}")
            else:
                digest = image_digest(image, image_tag, token)
                ok, detail = cosign_verifies(
                    cosign,
                    f"{REGISTRY}/{image}@{digest}",
                    f"https://github.com/{repository}/.github/workflows/container-image.yml@refs/tags/{tag}",
                )
                if ok:
                    print(f"{tag}: image {digest} verified.", file=out)
                else:
                    problem(f"{tag}: image {digest} does not verify: {detail}")

    # image -> releases
    for image_tag in tags:
        if IMAGE_SIGNATURE_TAG.match(image_tag):
            continue
        if f"v{image_tag}" not in commits:
            problem(f"image tag {image_tag}: no published release v{image_tag}")

    print(
        f"{len(problems)} mismatch(es)." if problems else "Everything matches.",
        file=out,
    )
    return not problems


def main(argv: list[str]) -> int:
    if len(argv) != 4 or "/" not in argv[1]:
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 1
    github = GitHub(argv[1], os.environ.get("GH_TOKEN") or None)
    try:
        with open(argv[3], encoding="utf-8") as file, tempfile.TemporaryDirectory() as workdir:
            trust = Trust(json.load(file), workdir)
            return 0 if check(argv[1], argv[2], trust, github, sys.stdout) else 1
    except (Unreadable, ValueError, KeyError, OSError) as error:
        print(f"UNREADABLE: {error}", file=sys.stdout)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
