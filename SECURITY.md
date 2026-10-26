# Security policy

`hodeishield` runs with your organisation's credentials, so we treat its security as part of the
product's.

## Reporting a vulnerability

**Do not open a public issue.** Report it privately through GitHub:
[**Report a vulnerability**](https://github.com/Hodeitek/hodeishield-cli/security/advisories/new)
(the *Security* tab of this repository → *Report a vulnerability*), or email
[security@hodeitek.com](mailto:security@hodeitek.com).

Please include the version (`hodeishield --version`), your platform, what you did, what happened and
what you expected, and a proof of concept if you have one. **Never include a real API key or token**:
if one was exposed, revoke it in the app first.

We will acknowledge your report, keep you informed while we investigate, and credit you in the
advisory if you want to be credited.

- Machine-readable contact: [security.txt](https://hodeishield.com/.well-known/security.txt)
  (RFC 9116), for the whole HodeiShield product. The same file is served on `app.hodeishield.com`
  and `docs.hodeishield.com`.
- Machine-readable contact for this CLI: [security.txt](.well-known/security.txt) (RFC 9116), published in
  this repository at `.well-known/security.txt` on `main`, where it is served as
  <https://raw.githubusercontent.com/Hodeitek/hodeishield-cli/main/.well-known/security.txt>. It is
  not signed. A weekly check validates it and opens an issue when it has less than 60 days left.
- Encrypted email: not offered at the moment.
- Bug bounty: there is no bounty programme; we credit reporters publicly in the advisory.

## What happens after you report

A report made through GitHub opens a draft security advisory that only you and the maintainers can
see; we talk to you there. A report made by email is answered by email.

| Step | What you get | When |
|---|---|---|
| Acknowledgement | Confirmation that we received the report | Within 3 business days |
| First assessment | Whether it is a vulnerability, its severity, and whether we know of it being exploited | Within 10 business days |
| Status updates | Progress on the fix and the expected release, until the advisory is published | At least every 14 days |
| Fix | A release that fixes it, and the published advisory | See the targets below |

### Severity and fix targets

We rate severity with [CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document) and use
its qualitative ratings. You can comment on the rating in the advisory or by email. The targets
below are for shipping a fixed release, counted from the first assessment.

| Severity | CVSS v3.1 base score | Target to ship a fix |
|---|---|---|
| Critical | 9.0 – 10.0 | 7 days |
| High | 7.0 – 8.9 | 30 days |
| Medium | 4.0 – 6.9 | 90 days |
| Low | 0.1 – 3.9 | The next release |

### Coordinated disclosure

We ask you to keep the vulnerability confidential until the advisory is published, and we agree
the publication date with you. The coordinated disclosure period is 90 days from your report. If
a fix is not released by then, we publish the advisory with the workarounds we know of, unless we
agree a short extension with you. If the vulnerability is being actively exploited,
we may publish earlier, with workarounds (see [Security notices](#security-notices)).

### Safe harbour

We will not take legal action against you, or ask anyone else to, for research that follows this
policy in good faith: you report to us privately and give us reasonable time to fix the issue before
you disclose it; you access only the data you need to show the vulnerability, and do not keep,
change or share anyone else's data; you do not degrade the service or harm its users; and you test
only against accounts and tenants you own or are allowed to use. If in doubt, ask us first.

## Security notices

If a release is affected by a vulnerability that is being actively exploited, or by a severe
incident (for example a compromised release or release pipeline), we tell users in these places,
in this order:

1. **The GitHub security advisory** for this repository, under
   [Security → Advisories](https://github.com/Hodeitek/hodeishield-cli/security/advisories). It is
   published or updated first, before a fix is available if necessary, and says which versions are
   affected, what to do in the meantime, and whether a fix is in progress.
2. **A short notice at the top of [README.md](README.md)**, linking to the advisory. The README
   keeps an empty block for it between the markers `<!-- security-notice:start -->` and
   `<!-- security-notice:end -->`; the notice goes between them, as a quote with a blank line
   before and after it:

   ```markdown
   <!-- security-notice:start -->

   > **Security notice:** versions 0.x.y to 0.x.z are affected by GHSA-xxxx-xxxx-xxxx. Update to
   > 0.x.w; until then, see the advisory for a workaround.

   <!-- security-notice:end -->
   ```

   The notice is updated when the fix ships and removed when it no longer applies, leaving the
   block empty. The README inside a release archive is a copy taken when that release was built:
   check the repository's README, not the copy you downloaded.
3. **The release notes of the release that fixes it**, under `### Security` in that release's
   section of [CHANGELOG.md](CHANGELOG.md), which the release workflow uses as the release notes.
   Each entry links to the advisory.

What the maintainers do when a signing credential or the release workflow is compromised, and what
such a notice then says, is described in [docs/release-signing.md](docs/release-signing.md).

To be told, watch this repository's releases on GitHub (*Watch → Custom → Releases*) or follow
[its releases feed](https://github.com/Hodeitek/hodeishield-cli/releases.atom), and check the
advisories page. The CLI's own [new-version notice](README.md#new-version-notice) tells you on an
interactive terminal that a newer release exists, but not whether it fixes a vulnerability.

## How advisories are published

Every fixed vulnerability gets a GitHub security advisory in this repository, written from
[docs/security-advisory-template.md](docs/security-advisory-template.md) so that every advisory has
the same fields:

- a description of the vulnerability and its impact;
- who is affected: which commands, configurations and install channels;
- the affected versions and the fixed versions;
- the severity, with its CVSS v3.1 vector;
- workarounds, how to check whether you are affected, and how to update;
- the timeline (reported, fixed, published), the credit, and references.

The advisory is published when the fixed release is out, or earlier as described in
[Security notices](#security-notices).

Each advisory has a GHSA identifier. Its machine-readable form is the advisory record that GitHub's
REST API returns, for example
`https://api.github.com/repos/Hodeitek/hodeishield-cli/security-advisories?state=published`, which
lists the identifiers, affected and patched versions, CVSS vector and credits as JSON. Advisories
are published on GitHub. When a vulnerability needs a CVE identifier, we request it through the
advisory, with GitHub as the CVE Numbering Authority.

## Supported versions

From 1.0.0, each major version of `hodeishield` is supported for five years, counted from the
release of its first version (1.0.0 for version 1). A supported major version receives security
fixes. They ship in a new release of that major version: to get them, update to the latest release
of your major version.

Security fixes stay available to you while your version is supported, even if your HodeiShield
subscription has ended: every release is a public download, and installing or updating the CLI
never requires a subscription.

**Before 1.0.** While the 0.x series is current, security fixes go into the latest 0.x release.
The 0.x series has no end-of-support date until 1.0.0 is released.

| Version | Supported | Security fixes until |
|---|---|---|
| 0.x | Yes, in the latest 0.x release | No end date until 1.0.0 is released |

The end-of-support date of each major version is published in this table and in the release
notes. Twelve months before a major version's support ends, an end-of-support notice is published
here, in the security notice block at the top of [README.md](README.md) (see
[Security notices](#security-notices)) and in the release notes.

## What is in scope

- Anything that could expose a credential: the tenant API key in `HODEISHIELD_API_KEY`, or the
  sign-in tokens the CLI keeps in the system keychain or, if the user opted in, in its token file
  (including the checks that refuse an unsafe file or directory).
- Sending a credential anywhere other than the configured HodeiShield hosts (redirects, plain HTTP,
  crafted URLs or identifiers).
- Output from the API reaching your terminal in a way that can run or hide commands.
- The release pipeline: a download that verifies (checksum, Sigstore signature, SLSA provenance) but
  was not built by this repository's release workflow.

A vulnerability in a component the CLI is built from is in scope when it affects the CLI. We pass it
to the component's maintainers and share any fix, as described in
[docs/third-party-components.md](docs/third-party-components.md#reporting-a-vulnerability-to-the-components-maintainers).

Vulnerabilities in the HodeiShield service itself are also welcome through the same channel; we route
them to the right team.

## What the CLI guarantees

- It only reads. The generated API client has no method other than `GET`.
- Credentials are never written to disk in clear text, printed, or logged (`--verbose` logs method,
  URL, status and request id only).
- Credentials are sent only over HTTPS (plain HTTP is accepted only for `localhost`), and redirects
  are never followed.
- Releases are signed keylessly with Sigstore from GitHub Actions and carry SLSA provenance; no
  long-lived key is involved in those signatures. The Windows executable and installer are also
  signed with Authenticode through Azure Artifact Signing, whose key never leaves that service. The
  APT and DNF package repository, once published, has its own OpenPGP key
  ([#114](https://github.com/Hodeitek/hodeishield-cli/issues/114)). See
  [docs/verifying-releases.md](docs/verifying-releases.md) and
  [docs/release-signing.md](docs/release-signing.md).

The risks these guarantees address, and how each security requirement of the Cyber Resilience Act is
met, are in [docs/risk-assessment.md](docs/risk-assessment.md).
