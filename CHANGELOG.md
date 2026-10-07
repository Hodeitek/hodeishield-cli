# Changelog

Notable changes to the `hodeishield` CLI, in the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
format. The CLI follows [Semantic Versioning](https://semver.org/); its scripting surface is the
commands, `--json` output and exit codes. Each release's notes start with its section below.

## [Unreleased]

### Added

- Each release publishes a CycloneDX SBOM per archive (`<archive>.cdx.json`): the crates compiled
  into that binary, signed with Sigstore and listed in `SHA256SUMS`.
  ([#34](https://github.com/Hodeitek/hodeishield-cli/issues/34))
- `--csv` on every `list` command and on `compliance controls` prints the items as CSV (RFC 4180,
  UTF-8, the same fields as `--json`), also with `--all`. Text cells that a spreadsheet would run
  as a formula are prefixed with `'`.
  ([#19](https://github.com/Hodeitek/hodeishield-cli/issues/19))

### Changed (scripting surface)

- **New exit code 8**: the tenant's licence is not in force. A `403` that the API marks as
  `LICENCE_INACTIVE` used to exit with 4 (missing scope); it now exits with 8. Scripts that treat 4
  as "get a key with the right scope" no longer see this case, which only a tenant administrator can
  fix. ([#47](https://github.com/Hodeitek/hodeishield-cli/issues/47))

### Changed

- Release notes start with the version's section of this changelog, and a release cannot be tagged
  without one. ([#24](https://github.com/Hodeitek/hodeishield-cli/issues/24))
- GET requests to the API are retried up to twice, with exponential backoff and jitter, on 502,
  503, 504 or a connection error or timeout, honouring `Retry-After`; other errors are not
  retried; `--verbose` logs each retry. ([#49](https://github.com/Hodeitek/hodeishield-cli/issues/49))

### Fixed

- A tenant with no licence in force is reported as such, with the licence state, instead of as a
  missing scope. ([#47](https://github.com/Hodeitek/hodeishield-cli/issues/47))

## [0.1.1] - 2026-09-30

### Changed

- The CLI limits how much it reads from any API answer (8 MiB) and how many items `--all` collects
  (100 000), and reports a clear error past either limit instead of exhausting memory.

## [0.1.0] - 2026-09-29

### Added

- First release: a read-only client for the HodeiShield `/v1` API, generated from its OpenAPI
  document. Commands for vendors, alerts, risks, compliance (controls and posture), evidence and
  endpoints, each with `list` (paging, `--all`, filters, sorting) and `get`.
- Sign-in with a tenant API key (`HODEISHIELD_API_KEY`) or with OAuth (`login` in the browser or
  with `--device`), tokens kept in the system keychain, `logout` and `whoami`.
- `--json` prints the API's own JSON; exit codes say what went wrong.
- Profiles (`config`), shell completions, and release archives for Linux, macOS and Windows signed
  with Sigstore and with SLSA provenance.

[Unreleased]: https://github.com/Hodeitek/hodeishield-cli/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/Hodeitek/hodeishield-cli/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Hodeitek/hodeishield-cli/releases/tag/v0.1.0
