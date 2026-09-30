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
advisory unless you prefer otherwise.

## Supported versions

Only the latest release receives fixes.

## What is in scope

- Anything that could expose a credential: the tenant API key in `HODEISHIELD_API_KEY`, or the
  sign-in tokens the CLI keeps in the system keychain.
- Sending a credential anywhere other than the configured HodeiShield hosts (redirects, plain HTTP,
  crafted URLs or identifiers).
- Output from the API reaching your terminal in a way that can run or hide commands.
- The release pipeline: a download that verifies (checksum, Sigstore signature, SLSA provenance) but
  was not built by this repository's release workflow.

Vulnerabilities in the HodeiShield service itself are also welcome through the same channel; we route
them to the right team.

## What the CLI guarantees

- It only reads. The generated API client has no method other than `GET`.
- Credentials are never written to disk in clear text, printed, or logged (`--verbose` logs method,
  URL, status and request id only).
- Credentials are sent only over HTTPS (plain HTTP is accepted only for `localhost`), and redirects
  are never followed.
- Releases are signed keylessly with Sigstore from GitHub Actions and carry SLSA provenance; no
  long-lived signing key exists. See [docs/verifying-releases.md](docs/verifying-releases.md).
