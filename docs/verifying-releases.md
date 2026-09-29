# Verifying releases

Every release of `hodeishield-cli` publishes, for each platform archive:

- `SHA256SUMS` — checksums of every archive.
- `<archive>.sigstore.json` and `SHA256SUMS.sigstore.json` — Sigstore
  "bundle" files produced by **keyless** `cosign sign-blob` (no private key:
  the workflow signs using its GitHub Actions OIDC identity, and the
  signature is recorded in the public Rekor transparency log).
- `hodeishield.intoto.jsonl` — [SLSA](https://slsa.dev) build provenance for the
  release, produced by the
  [`slsa-framework/slsa-github-generator`](https://github.com/slsa-framework/slsa-github-generator)
  generic generator.

The steps below use `v0.1.0` and `hodeishield-0.1.0-x86_64-unknown-linux-musl.tar.gz`
as examples — substitute the actual version and archive you downloaded.

## 1. Download the files

From the release page, download:

- the archive you want (e.g. `hodeishield-0.1.0-x86_64-unknown-linux-musl.tar.gz`)
- `SHA256SUMS`
- the matching `<archive>.sigstore.json`
- `SHA256SUMS.sigstore.json`
- `hodeishield.intoto.jsonl` (the provenance)

## 2. Check the checksum

```sh
sha256sum -c SHA256SUMS --ignore-missing
```

This confirms the archive you downloaded matches the checksum the release
workflow recorded. It does **not** by itself prove who built it — that's
what the next two steps are for.

## 3. Verify the Sigstore signature

Requires [`cosign`](https://github.com/sigstore/cosign) (v2 or newer).

```sh
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity https://github.com/Hodeitek/hodeishield-cli/.github/workflows/release.yml@refs/tags/v0.1.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-github-workflow-trigger push \
  SHA256SUMS
```

Repeat for the archive itself, using its own `.sigstore.json`:

```sh
cosign verify-blob \
  --bundle hodeishield-0.1.0-x86_64-unknown-linux-musl.tar.gz.sigstore.json \
  --certificate-identity https://github.com/Hodeitek/hodeishield-cli/.github/workflows/release.yml@refs/tags/v0.1.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-github-workflow-trigger push \
  hodeishield-0.1.0-x86_64-unknown-linux-musl.tar.gz
```

A successful verification confirms the file was signed by the
`release.yml` workflow of the `Hodeitek/hodeishield-cli` repository, run by the
push of **exactly the tag you expect** — not by an arbitrary contributor, a
fork, a manual run, or an older release renamed to look like this one. Use the
exact identity with your version, not a pattern that any `v*` tag would match.

## 4. Verify SLSA build provenance

Requires [`slsa-verifier`](https://github.com/slsa-framework/slsa-verifier).

```sh
slsa-verifier verify-artifact \
  hodeishield-0.1.0-x86_64-unknown-linux-musl.tar.gz \
  --provenance-path hodeishield.intoto.jsonl \
  --source-uri github.com/Hodeitek/hodeishield-cli \
  --source-tag v0.1.0
```

`hodeishield.intoto.jsonl` is attached to the release and covers every
archive of that release.

This confirms the archive was built by the `release.yml` GitHub Actions
workflow, from the `Hodeitek/hodeishield-cli` source repository, at the tag
you expect — not from a modified build or a malicious fork.

## Not yet

The following distribution methods are planned but not part of this
release:

- **Homebrew tap** — not yet published.
- **MSI installer for Windows** — not yet provided; use the `.zip` archive.
