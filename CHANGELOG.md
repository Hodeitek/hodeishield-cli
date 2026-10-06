# Changelog

Notable changes to the `hodeishield` CLI. Releases up to 0.1.1 are described on the
[releases page](https://github.com/Hodeitek/hodeishield-cli/releases).

## Unreleased

### Changed (scripting surface)

- **New exit code 8**: the tenant's licence is not in force. A `403` that the API marks as
  `LICENCE_INACTIVE` used to exit with 4 (missing scope); it now exits with 8. Scripts that treat 4
  as "get a key with the right scope" no longer see this case, which only a tenant administrator can
  fix. ([#47](https://github.com/Hodeitek/hodeishield-cli/issues/47))

### Changed

- GET requests to the API are retried up to twice, with exponential backoff and jitter, on 502,
  503, 504 or a connection error or timeout, honouring `Retry-After`; other errors are not
  retried; `--verbose` logs each retry. ([#49](https://github.com/Hodeitek/hodeishield-cli/issues/49))

### Fixed

- A tenant with no licence in force is reported as such, with the licence state, instead of as a
  missing scope. ([#47](https://github.com/Hodeitek/hodeishield-cli/issues/47))
