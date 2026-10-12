# Release signing

This document lists the credentials and identities that sign `hodeishield` releases, who may change
them, and what the maintainers do if one of them is compromised. To check a download, see
[verifying-releases.md](verifying-releases.md). How users are told about an incident is described in
[SECURITY.md](../SECURITY.md#security-notices).

## Signatures and identities

### Sigstore signatures of the release files

The `publish` job of `.github/workflows/release.yml` signs every release file and `SHA256SUMS` with
`cosign sign-blob`, keylessly. cosign gets a short-lived certificate from Sigstore's Fulcio for the
job's GitHub Actions OIDC token, and the signature is recorded in the public Rekor transparency log.
No private key is stored anywhere.

The certificate names the workflow and the tag that ran it. This is the identity users verify:

```text
https://github.com/Hodeitek/hodeishield-cli/.github/workflows/release.yml@refs/tags/v<version>
```

with the issuer `https://token.actions.githubusercontent.com` and the trigger `push`. The
certificate also records the repository, the commit the tag points to and the workflow run.

The identity depends on three things only: the repository name, the path of the workflow file and
the tag. It changes if the workflow file is renamed or moved, or if the repository is renamed or
transferred.

### SLSA provenance

The `provenance` job runs the generic generator of
[`slsa-github-generator`](https://github.com/slsa-framework/slsa-github-generator) v2.1.0, which
signs `hodeishield.intoto.jsonl` keylessly in the same way. Its certificate names the generator's
own workflow, which is also the builder recorded in the provenance:

```text
https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0
```

The provenance records the source repository, the tag, its commit and the entry point
`.github/workflows/release.yml`. `slsa-verifier` checks the source and the tag
([verifying-releases.md](verifying-releases.md#4-verify-slsa-build-provenance)). A new generator
version changes the builder identity; it comes with a change to `release.yml`.

### Container image

When a release is published, the **Container image** workflow signs the image by digest, and its
SBOM attestation, keylessly in the same way, after the `packaging` environment's approval. The
identity is
`https://github.com/Hodeitek/hodeishield-cli/.github/workflows/container-image.yml@refs/tags/v<version>`
with the trigger `release` ([README.md](../README.md#container-image)).

### Authenticode (Windows)

The `sign-windows` and `sign-msi` jobs of `release.yml` sign `hodeishield.exe` (x64 and arm64) and
the x64 MSI with [Azure Artifact Signing](https://learn.microsoft.com/azure/artifact-signing/), with
an RFC 3161 timestamp from `http://timestamp.acs.microsoft.com`.

- **Account and certificate profile.** The `release-signing` environment variables
  `AZURE_SIGNING_ENDPOINT`, `AZURE_SIGNING_ACCOUNT_NAME` and `AZURE_CERTIFICATE_PROFILE_NAME` name
  them.
- **Access.** The jobs log in with `azure/login` through OIDC federation: a federated credential
  trusts only this repository's `release-signing` environment. The environment secrets
  `AZURE_CLIENT_ID`, `AZURE_TENANT_ID` and `AZURE_SUBSCRIPTION_ID` are directory identifiers, not
  keys.
- **Private key.** It is generated and kept in the service's hardware security modules and cannot be
  exported. There is no certificate, password or `.pfx` in the repository, in its secrets or on the
  runner.
- **Certificates.** The service issues a new certificate for the profile every day, valid for 72
  hours. The timestamp keeps a signature valid after its certificate expires. The thumbprint
  therefore differs from one release to another. What stays the same for the life of the profile is
  the subject and an Extended Key Usage (EKU) value unique to the profile.
- **Switch.** The repository variable `WINDOWS_SIGNING_ENABLED` turns the signing on, and only for a
  run started by a pushed `v*` tag.

The signatures of every signed release so far (0.2.0 to 0.4.1) carry:

| Field | Value |
|---|---|
| Subject | `CN=Hodeitek S.L., O=Hodeitek S.L., L=Aretxabaleta, S=Gipuzkoa, C=ES` |
| Certificate profile EKU | `1.3.6.1.4.1.311.97.449523565.535854065.272767902.439799148` |

### macOS

macOS signing is not active ([#50](https://github.com/Hodeitek/hodeishield-cli/issues/50)):
`MACOS_SIGNING_ENABLED` is not set, and no Apple certificate or notarization key is stored. The
workflow's macOS steps would use Developer ID certificates and an App Store Connect key kept as
`release-signing` environment secrets. This document must cover them before they are used.

### Package repository key

The APT and DNF package repository, once it is published, signs its indexes with its own OpenPGP
key, which this document does not cover. The procedure after a revocation of that key is tracked
separately in [#114](https://github.com/Hodeitek/hodeishield-cli/issues/114).

## Who may change them

- **The release workflow.** `release.yml` changes through pull requests
  ([CONTRIBUTING.md](../CONTRIBUTING.md#pull-requests)). `main` accepts changes only through a pull
  request with passing checks and signed commits, for administrators too.
- **Release tags.** The `release tags` ruleset protects `v*` tags: only members of the
  organisation's release team can create, move or delete one. A tag runs the `release.yml` of the commit it points to, so this
  ruleset is what guards the Sigstore identity. In the current `release.yml`, the Sigstore signing
  runs after the Windows signing jobs, which wait for an approval, but needs no approval of its own:
  a `release.yml` changed at a tag could sign without one.
- **The `release-signing` environment.** Every job that uses it waits for a required reviewer, and
  only a `v*` tag can deploy to it. It holds the Azure identifiers and the signing account names.
- **The `packaging` environment.** The same protections. It gates the package managers and the
  container image.
- **Repository settings.** Repository administrators manage the repository variables, the
  environments with their reviewers, secrets and variables, and the ruleset.
- **Azure.** The signing account, its identity validations and certificate profiles, and the Azure
  identity that holds the federated credential are managed in the Azure subscription of the account.
  Revoking a certificate needs the Owner role on that subscription and is done in the Azure portal.
- **Sigstore and SLSA.** No credential exists to hold or change. The identity follows from the
  repository, the workflow file and the tag.

## If the Windows signing is compromised

This applies when the certificate profile, the signing account, the Azure identity that can sign
through it or the `release-signing` environment is compromised, or when a file is found signed with
the profile that the release workflow did not sign.

1. **Stop signing.**
   - Set the repository variable `WINDOWS_SIGNING_ENABLED` to `false`. A release built meanwhile has
     no MSI and an unsigned `hodeishield.exe`: do not publish one before step 4.
   - Reject any pending deployment to `release-signing` and cancel running Release workflow runs.
   - In Azure, remove the federated credential that trusts the `release-signing` environment, so no
     workflow run can get a session for the account.
2. **Find the window.** The signing account lists every certificate issued for the profile, with its
   serial number, thumbprint, creation and expiry dates and status. Compare them with the
   certificates in the signatures of the published files. The "Verify the Authenticode signature"
   steps also print the signer certificate in each release run's log. The window starts at the
   earliest time a signature not made by a release run may exist.
3. **Revoke.** In the Azure portal, under the certificate profile, revoke each certificate issued
   during the window, with the start of the window as its revocation date and time. Every file
   signed with a revoked certificate is invalid from that time; signatures timestamped earlier stay
   valid. Revocation cannot be undone. A release signed with the same certificate after that time
   becomes invalid too, and is replaced in step 5. For misuse, also contact Microsoft support, as
   [Microsoft's revocation guide](https://learn.microsoft.com/azure/artifact-signing/how-to-cert-revocation)
   says.
4. **Replace.** Create a new certificate profile, after a new identity validation if the old one is
   affected. A new profile has a new profile EKU. The subject comes from the identity validation and
   stays the same for the same organisation. If the account or the Azure identity is affected, create
   new ones, with a new federated credential that trusts only the `release-signing` environment, and
   update the environment's secrets and variables. Then set `WINDOWS_SIGNING_ENABLED` back to `true`.
5. **Sign again, in a new release.** A published file cannot be signed again in place. The
   Authenticode signature is part of the `.exe` and the `.msi`, so a file signed again has a new
   SHA-256: it no longer matches the release's `SHA256SUMS`, its Sigstore signatures or its
   provenance, and the release tag cannot be moved to sign them again. Publish a new patch release
   of each [supported version](../SECURITY.md#supported-versions) through the normal release
   process. The package managers and the MSI upgrade pick it up from there.
6. **Tell users,** in the order of [SECURITY.md](../SECURITY.md#security-notices):
   - the GitHub security advisory, written from
     [the template](security-advisory-template.md). It names the affected versions (every release
     whose Windows files carry a revoked certificate), the SHA-256 of any file known to be signed
     outside the release workflow, the window in UTC, the old and the new profile EKU, and what to
     do;
   - the notice at the top of [README.md](../README.md);
   - a `### Security` entry in the release notes of the new release.

   Add a line at the top of the notes of each affected release, linking to the advisory.
7. **Update the documents.** Put the new profile EKU, and the first version signed with it, in this
   document and in [verifying-releases.md](verifying-releases.md#6-releases-after-a-signing-change).

Windows users check the new signature as described in
[verifying-releases.md](verifying-releases.md#5-platform-signatures-windows-macos-in-a-later-release):
`Status` is `Valid`, the subject names Hodeitek S.L., a timestamp is present, and the profile EKU is
the new one given in the advisory.

## If the release workflow identity is compromised

This applies when a malicious change to `release.yml` reaches a tag, when a token or account that can
create `v*` tags leaks, when a release, tag or release file appears that the maintainers did not
publish, or when Sigstore signatures with this repository's identity exist that belong to no
release the maintainers published.

A Sigstore signature cannot be revoked. Its certificate expires within minutes and its Rekor entry is
permanent, so a file signed by a rogue run keeps verifying against the identity of its own tag.
Users are protected by verifying the exact tag of a release the maintainers published, and by the
advisory, which names the tags not to trust.

1. **Stop.**
   - Disable the Release workflow (*Actions → Release → Disable workflow*), and the Package managers
     and Container image workflows, which publish from a published release:

     ```sh
     gh workflow disable release.yml
     gh workflow disable package-managers.yml
     gh workflow disable container-image.yml
     ```

   - Reject any pending deployment to `release-signing` and `packaging`, and cancel running runs.
   - Revoke the leaked token, or remove the compromised account's access. Review who has the
     administrator role or is in the release team: they can create `v*` tags, and administrators can
     change the protections.
   - If a rogue run may have reached `release-signing`, follow the Windows section as well.
2. **Find what is affected.** List the `v*` tags and the releases, drafts included
   (`gh release list`), the Release workflow runs with the event and the user that started them, and
   the changes to `.github/workflows/release.yml` in the tagged commits. For each release, record
   its tag, commit and `SHA256SUMS`. A file found elsewhere can be looked up in the Rekor log by its
   SHA-256 (`rekor-cli search --sha <digest>`, or [search.sigstore.dev](https://search.sigstore.dev)),
   which shows the identity and commit in its certificate.
3. **Remove or mark the releases.**
   - A release that must not be used is deleted with its files and its tag, after step 2 has
     recorded them. Its version number is never used again: its signatures stay in Rekor under that
     tag's identity.
   - A release that stays available but is affected gets a line at the top of its notes, linking to
     the advisory.
   - Undo what was published from an affected release: revert the commits in the Homebrew tap and
     the Scoop bucket, ask for the winget manifest to be removed, and delete the container image
     version. The package repository is covered by
     [#114](https://github.com/Hodeitek/hodeishield-cli/issues/114).
4. **Tell users,** in the order of [SECURITY.md](../SECURITY.md#security-notices): the advisory,
   which names the affected versions and tags, their commits, the SHA-256 of the affected files, the
   window in UTC and what to do; the notice at the top of [README.md](../README.md); and a
   `### Security` entry in the release notes of the next release.
5. **Restore.** Fix the workflow through a reviewed pull request. Check the environments, their
   reviewers, the ruleset and the administrators. Enable the workflows again and publish a new
   release, with a new version number.
6. **If the identity changes.** It changes when the workflow file is renamed or moved, or the
   repository is renamed or transferred, for example to make a clean break after a compromise.
   Every place that pins it then changes in the same release:
   [verifying-releases.md](verifying-releases.md), [README.md](../README.md), `install.sh`, `.github/workflows/package-managers.yml`,
   `.github/workflows/container-image.yml` and this document. The release notes and the advisory
   give the new identity and the first version signed with it. Earlier releases keep the identity
   they were signed with, and are verified with it.

Users tell a genuine release apart as described in
[verifying-releases.md](verifying-releases.md#6-releases-after-a-signing-change): the exact identity
with their tag, the commit the advisory names, and the provenance's source and tag.
