# Verifying releases

Every release of `hodeishield-cli` publishes, for each platform archive:

- `SHA256SUMS` — checksums of every archive.
- `<archive>.sigstore.json` and `SHA256SUMS.sigstore.json` — Sigstore
  "bundle" files produced by **keyless** `cosign sign-blob` (no private key:
  the workflow signs using its GitHub Actions OIDC identity, and the
  signature is recorded in the public Rekor transparency log).
- `hodeishield-<version>-aarch64-pc-windows-msvc.zip` (Windows on Arm, from 0.4.0),
  checksummed, signed with Sigstore, covered by the provenance and accompanied by its
  SBOM like the other archives. Its `hodeishield.exe` carries the same Authenticode signature
  (section 5). There is no arm64 MSI yet.
- `hodeishield-<version>-x86_64-pc-windows-msvc.msi` (from 0.3.0), with its own
  `.sigstore.json` and listed in `SHA256SUMS`. The MSI and the `hodeishield.exe` inside it are both
  signed with Authenticode (section 5); the exe is the same as in the `.zip`, whose SBOM describes it.
- `.deb` and `.rpm` packages (from 0.3.0), each with its own `.sigstore.json` and
  listed in `SHA256SUMS`. They contain the binary and man pages of the Linux archive for the same
  architecture, so that archive's SBOM describes them; verify them the same way as the archives.
- `<archive-name>.cdx.json` — a [CycloneDX](https://cyclonedx.org) SBOM for each archive (from
  0.2.0): every crate compiled into that binary, with its version, licence and package URL. It has
  its own `.sigstore.json`, and is listed in `SHA256SUMS`.
- `hodeishield.intoto.jsonl` — [SLSA](https://slsa.dev) build provenance for the
  release, produced by the
  [`slsa-framework/slsa-github-generator`](https://github.com/slsa-framework/slsa-github-generator)
  generic generator.

From 0.4.2, every archive, `.deb`, `.rpm` and MSI also contains `USER-INFORMATION.md`, the
[user information](user-information.md) for that release, so verifying the download verifies it
too. The `.deb` and `.rpm` install it in `/usr/share/doc/hodeishield/`, the MSI next to
`hodeishield.exe`.

The steps below use `v0.6.0` and `hodeishield-0.6.0-x86_64-unknown-linux-musl.tar.gz`
as examples — substitute the actual version and archive you downloaded.

## 1. Download the files

From the release page, download:

- the archive you want (e.g. `hodeishield-0.6.0-x86_64-unknown-linux-musl.tar.gz`)
- `SHA256SUMS`
- the matching `<archive>.sigstore.json`
- `SHA256SUMS.sigstore.json`
- `hodeishield.intoto.jsonl` (the provenance)

## 2. Check the checksum

```sh
grep hodeishield-0.6.0-x86_64-unknown-linux-musl.tar.gz SHA256SUMS | sha256sum -c -
```

Checking only the line of your archive works with GNU `sha256sum` and with the BusyBox one on
Alpine, which has no `--ignore-missing`. On macOS, use `shasum -a 256 -c` in place of `sha256sum -c`.

This confirms the archive you downloaded matches the checksum the release
workflow recorded. It does **not** by itself prove who built it — that's
what the next two steps are for.

## 3. Verify the Sigstore signature

Requires [`cosign`](https://github.com/sigstore/cosign) v3. With cosign v2 (2.4 or newer), add
`--new-bundle-format` to each `cosign verify-blob` command below: the signatures are Sigstore bundles
in the format cosign v3 reads by default. Older cosign versions cannot read them.

```sh
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity https://github.com/Hodeitek/hodeishield-cli/.github/workflows/release.yml@refs/tags/v0.6.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-github-workflow-trigger push \
  SHA256SUMS
```

Repeat for the archive itself, using its own `.sigstore.json`:

```sh
cosign verify-blob \
  --bundle hodeishield-0.6.0-x86_64-unknown-linux-musl.tar.gz.sigstore.json \
  --certificate-identity https://github.com/Hodeitek/hodeishield-cli/.github/workflows/release.yml@refs/tags/v0.6.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-github-workflow-trigger push \
  hodeishield-0.6.0-x86_64-unknown-linux-musl.tar.gz
```

A successful verification confirms the file was signed by the
`release.yml` workflow of the `Hodeitek/hodeishield-cli` repository, run by the
push of **exactly the tag you expect** — not by an arbitrary contributor, a
fork, a manual run, or an older release renamed to look like this one. Use the
exact identity with your version, not a pattern that any `v*` tag would match.

The SBOM is verified the same way, with its own bundle:

```sh
cosign verify-blob \
  --bundle hodeishield-0.6.0-x86_64-unknown-linux-musl.cdx.json.sigstore.json \
  --certificate-identity https://github.com/Hodeitek/hodeishield-cli/.github/workflows/release.yml@refs/tags/v0.6.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-github-workflow-trigger push \
  hodeishield-0.6.0-x86_64-unknown-linux-musl.cdx.json
```

## 4. Verify SLSA build provenance

Requires [`slsa-verifier`](https://github.com/slsa-framework/slsa-verifier).

```sh
slsa-verifier verify-artifact \
  hodeishield-0.6.0-x86_64-unknown-linux-musl.tar.gz \
  --provenance-path hodeishield.intoto.jsonl \
  --source-uri github.com/Hodeitek/hodeishield-cli \
  --source-tag v0.6.0
```

`hodeishield.intoto.jsonl` is attached to the release and covers every
archive of that release.

This confirms the archive was built by the `release.yml` GitHub Actions
workflow, from the `Hodeitek/hodeishield-cli` source repository, at the tag
you expect — not from a modified build or a malicious fork.

## 5. Platform signatures (Windows, macOS)

From 0.2.0, `hodeishield.exe` also carries an Authenticode signature, which Windows checks by
itself. It does not replace the steps above: it says the file comes from Hodeitek, not which
workflow run built it.

```powershell
Get-AuthenticodeSignature .\hodeishield.exe | Format-List Status, SignerCertificate, TimeStamperCertificate
```

`Status` must be `Valid` and the signer's subject must name Hodeitek S.L. In Explorer the same
information is under Properties → Digital Signatures. The same check applies to the `.msi`
(`Get-AuthenticodeSignature .\hodeishield-<version>-x86_64-pc-windows-msvc.msi`).

The signing certificate is renewed every day, so its thumbprint differs between releases. What
identifies the certificate profile that signed the file is an Extended Key Usage (EKU) value that
starts with `1.3.6.1.4.1.311.97.`. To list the EKU values:

```powershell
(Get-AuthenticodeSignature .\hodeishield.exe).SignerCertificate.Extensions |
  Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] } |
  ForEach-Object { $_.EnhancedKeyUsages } | Select-Object Value, FriendlyName
```

From 0.2.0 the profile EKU is `1.3.6.1.4.1.311.97.449523565.535854065.272767902.439799148`
([release-signing.md](release-signing.md#authenticode-windows) lists it with the subject).

### macOS

This applies from the first release signed with a Developer ID; earlier macOS binaries are not
signed or notarized, and the release's run summary says whether a release's macOS files are. For a
release that is signed, the binary carries a Developer ID Application signature and is notarized by
Apple, and the `.pkg` installer carries a Developer ID Installer signature, is notarized and has its
ticket stapled.

```sh
# The binary: signed by Hodeitek's Developer ID, with the hardened runtime and a timestamp.
codesign -dvv ./hodeishield 2>&1 | grep -E 'Authority|TeamIdentifier|Timestamp|flags'
codesign --verify --strict --verbose=2 ./hodeishield

# Gatekeeper's verdict. Expect "accepted" and "source=Notarized Developer ID". A bare
# executable cannot be stapled, so this check needs a network connection.
spctl -a -vv -t exec ./hodeishield

# The installer package.
pkgutil --check-signature hodeishield-<version>-universal-apple-darwin.pkg
xcrun stapler validate hodeishield-<version>-universal-apple-darwin.pkg
```

`Authority` must list `Developer ID Application: Hodeitek S.L.`, and `TeamIdentifier` must be the
Team ID that [release-signing.md](release-signing.md#developer-id-macos) and the release notes give.
The package must show a `Developer ID Installer: Hodeitek S.L.` certificate. As with Windows, this
says the file comes from Hodeitek; the Sigstore and SLSA checks above say which workflow run built
it.

## 6. Releases after a signing change

If a signing credential or the release workflow is ever compromised or replaced, the maintainers
publish a notice as described in [SECURITY.md](../SECURITY.md#security-notices): first the GitHub
security advisory, then a notice at the top of [README.md](../README.md), then the release notes of
the release that follows the change. The advisory names the affected versions and the first release
signed after the change. [release-signing.md](release-signing.md) describes what the maintainers do.

What can change:

- **Windows.** A new certificate profile has a new profile EKU (section 5). The advisory and
  [release-signing.md](release-signing.md#authenticode-windows) give the new value and the first
  version signed with it. The subject still names Hodeitek S.L.
- **Sigstore identity.** It changes only if the workflow file is renamed or moved, or the repository
  is renamed or transferred. The advisory and the release notes then give the new identity and the
  first version signed with it. Earlier releases keep the identity they were signed with.
- **Tags not to trust.** A tag that a compromised workflow or token produced keeps verifying
  against its own identity, because a Sigstore signature cannot be revoked. The advisory lists those
  tags, with their commits and the SHA-256 of their files. Their version numbers are never used
  again.

What does not change:

- A published file is never signed again in place. A fix comes as a new version, with its own tag,
  checksums, signatures and provenance.
- You always verify with the exact tag of the version you downloaded, the issuer
  `https://token.actions.githubusercontent.com` and the trigger `push`.

The certificate of each Sigstore signature also records the commit that was built. When an
advisory names the commit of a genuine release, add it to the check:

```sh
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity https://github.com/Hodeitek/hodeishield-cli/.github/workflows/release.yml@refs/tags/v<version> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-github-workflow-trigger push \
  --certificate-github-workflow-sha <commit> \
  SHA256SUMS
```

The provenance check (section 4) confirms the same source repository and tag. Every signature is
also in the public Rekor transparency log: `rekor-cli search --sha <sha256 of the file>`, or
[search.sigstore.dev](https://search.sigstore.dev), lists the log entries for a file, with the
identity and commit in each certificate.

## 7. Rebuild the Linux binaries

From 0.4.3, you can rebuild the Linux binaries from the tag and get the same bytes as
the release. The build runs in a container image pinned by digest (`packaging/build/image`): the
Rust toolchain of `rust-toolchain.toml`, the Debian packages from a fixed snapshot of the Debian
archive, and the crates locked in `Cargo.lock`. The repository is mounted at the same path inside
the container wherever it is on your machine, so the result does not depend on where you clone it.

You need git, Docker, network access to crates.io and Debian's snapshot archive, and a machine of
the same architecture as the binary (x86_64 or aarch64).

```sh
git clone --branch v<version> https://github.com/Hodeitek/hodeishield-cli.git
cd hodeishield-cli
packaging/build/build.sh x86_64-unknown-linux-musl
sha256sum target/build-image/x86_64-unknown-linux-musl/release/hodeishield
```

Then compare the result with the binary in the release archive, after checking the archive as in
section 2:

```sh
tar -xzf hodeishield-<version>-x86_64-unknown-linux-musl.tar.gz
sha256sum hodeishield-<version>-x86_64-unknown-linux-musl/hodeishield
```

The two SHA-256 values must be the same. The `.deb` and `.rpm` packages install the same binary as
`/usr/bin/hodeishield`, and the container image carries it as `/usr/local/bin/hodeishield`.

The `Reproducible build` workflow (`.github/workflows/reproducible-build.yml`) does the same for both
architectures whenever a release is published, and opens an issue labelled `reproducible-build` if
the bytes differ. The macOS and Windows binaries cannot be rebuilt this way yet
([#170](https://github.com/Hodeitek/hodeishield-cli/issues/170)).

## Not yet

The following distribution methods are not part of the latest release:

- **winget package** — submitted, awaiting review by the winget community repository.
