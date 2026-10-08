# Changelog

Notable changes to the `hodeishield` CLI, in the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
format. The CLI follows [Semantic Versioning](https://semver.org/); its scripting surface is the
commands, `--json` output and exit codes. Each release's notes start with its section below.

## [Unreleased]

### Fixed

- `hodeishield login` now checks that the system keychain can keep a session before it opens the
  browser or shows a device code, and stops there with the usual pointer to API keys. If saving the
  session still fails after the app has issued tokens, the CLI revokes the refresh token and then
  the access token, says so on standard error and exits non-zero, instead of leaving an active
  grant that nothing holds. ([#101](https://github.com/Hodeitek/hodeishield-cli/issues/101))

### Added

- On an interactive terminal, the CLI now tells you in one line on standard error when a newer
  release exists. It asks GitHub's public releases API (no credential or identifier is sent) at most
  once a day, stays silent with `--json`, `--csv`, `completions`, when standard error is not a
  terminal and when `CI` is set, and never changes a command's output or exit code. Turn it off with
  `HODEISHIELD_NO_UPDATE_CHECK=1` or `hodeishield config set update_check false`; the README's "New-version
  notice" section lists exactly what is sent.
  ([#38](https://github.com/Hodeitek/hodeishield-cli/issues/38))
- A container image, `ghcr.io/hodeitek/hodeishield-cli`, for `linux/amd64` and `linux/arm64`: the
  release's own binary on a distroless base, running as a non-root user, tagged with the exact
  version only. It is signed by digest with Sigstore and carries the release's SBOM as a signed
  attestation. ([#36](https://github.com/Hodeitek/hodeishield-cli/issues/36))

## [0.3.0] - 2026-10-07

### Added

- Homebrew (`brew tap hodeitek/hodeishield`) and Scoop (`scoop bucket add hodeishield …`) packages,
  written from each published release's verified `SHA256SUMS`. The manifests for winget
  (`Hodeitek.HodeiShield`) are written by each release too; the package is submitted to the winget
  community repository and is not available yet.
  ([#21](https://github.com/Hodeitek/hodeishield-cli/issues/21),
  [#22](https://github.com/Hodeitek/hodeishield-cli/issues/22))
- A Windows installer (`.msi`), signed with Authenticode: installs for all users in
  `%ProgramFiles%\HodeiShield CLI`, adds it to `PATH`, upgrades in place, and supports silent
  installation for Intune and Group Policy.
- `.deb` and `.rpm` packages for x86_64 and arm64, with the man pages and the bash, zsh and fish
  completions, signed with Sigstore and listed in `SHA256SUMS`.
  ([#35](https://github.com/Hodeitek/hodeishield-cli/issues/35))
- `install.sh` for Linux and macOS, published and signed with each release: it checks the archive
  against `SHA256SUMS` and its Sigstore signature before installing the binary and its man pages.

## [0.2.0] - 2026-10-07

### Added

- **Signed Windows binary.** `hodeishield.exe` is signed with Authenticode, so Windows accepts it
  without manual unblocking. macOS signing and notarization come in a later release. Sigstore
  signatures and SLSA provenance continue as before for every archive.
  ([#50](https://github.com/Hodeitek/hodeishield-cli/issues/50))
- Each release publishes a CycloneDX SBOM per archive (`<archive>.cdx.json`): the crates compiled
  into that binary, signed with Sigstore and listed in `SHA256SUMS`.
  ([#34](https://github.com/Hodeitek/hodeishield-cli/issues/34))
- A man page for every command (`man hodeishield`, `man hodeishield-vendors-list`, …), generated
  from the command-line definition and shipped in the Linux and macOS archives under `man/`.
  ([#28](https://github.com/Hodeitek/hodeishield-cli/issues/28))
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

[Unreleased]: https://github.com/Hodeitek/hodeishield-cli/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/Hodeitek/hodeishield-cli/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Hodeitek/hodeishield-cli/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/Hodeitek/hodeishield-cli/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Hodeitek/hodeishield-cli/releases/tag/v0.1.0
