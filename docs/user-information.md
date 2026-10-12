# User information

This document gathers in one place what you need to know to use `hodeishield` securely: who makes
it, how to reach us, how long it is supported, and how to update and remove it. Where the details
live in [README.md](../README.md) or [SECURITY.md](../SECURITY.md), it links to them.

Each release keeps the copy of this document that applies to it, in that release's tag:
`https://github.com/Hodeitek/hodeishield-cli/blob/v<version>/docs/user-information.md`. Releases
after 0.4.1 also ship that copy with the product, as `USER-INFORMATION.md`: next to the binary in
every release archive, in `/usr/share/doc/hodeishield/` from the `.deb` and `.rpm` packages, in
`%ProgramFiles%\HodeiShield CLI` from the MSI, and in `$(brew --prefix)/share/doc/hodeishield` from
Homebrew. The container image does not include it. The shipped copy's links to other files are
relative to the repository: open them in the same tag. Releases up to 0.3.1 were published before
this document existed; for them, the README and SECURITY.md in their tag apply.

## Product

- **Name:** HodeiShield CLI. The command is `hodeishield` (`hodeishield.exe` on Windows); the
  source repository is [Hodeitek/hodeishield-cli](https://github.com/Hodeitek/hodeishield-cli).
- **Version:** `hodeishield --version` prints the installed version. Versions follow
  [Semantic Versioning](https://semver.org/) and each release is tagged `v<version>`.
- **Releases:** every release, with its files and notes, is on the
  [releases page](https://github.com/Hodeitek/hodeishield-cli/releases), at
  `https://github.com/Hodeitek/hodeishield-cli/releases/tag/v<version>`. The notes of every
  release, with its date, are also in [CHANGELOG.md](../CHANGELOG.md).

## Manufacturer and contact

Hodeitek S.L., Markole 17, 20550 Aretxabaleta, Gipuzkoa, Spain.

- Email: [info@hodeitek.com](mailto:info@hodeitek.com)
- Website: [hodeitek.com](https://hodeitek.com)
- Bug reports and documentation problems that are not about security:
  [GitHub issues](https://github.com/Hodeitek/hodeishield-cli/issues), as described in
  [CONTRIBUTING.md](../CONTRIBUTING.md).

## Reporting a vulnerability

The point of contact for vulnerabilities in `hodeishield` is the maintainers, through either of
these two means:

- [GitHub private vulnerability reporting](https://github.com/Hodeitek/hodeishield-cli/security/advisories/new)
  (the *Security* tab of the repository → *Report a vulnerability*);
- email to [security@hodeitek.com](mailto:security@hodeitek.com).

Never report a vulnerability in a public issue. What to include, how quickly you get an answer and
how a fix is disclosed are in [SECURITY.md](../SECURITY.md#what-happens-after-you-report). Published
advisories are under
[Security → Advisories](https://github.com/Hodeitek/hodeishield-cli/security/advisories), and
[Security notices](../SECURITY.md#security-notices) lists where an affected release is announced.

## Intended purpose

`hodeishield` is a read-only command-line client for the public `/v1` API of
[HodeiShield](https://hodeishield.com). It reads one organisation's third-party inventory,
supply-chain alerts, risk register, compliance posture, evidence and endpoint agents, from a
terminal or a script. Every command reads: its requests to the API are `GET` only, and it cannot
change data in your organisation. It needs a HodeiShield account to sign in with, or a tenant API
key.

## Security properties and secure use

What the CLI guarantees (read only, credentials never written to disk in clear text, printed or
logged, HTTPS only, no redirects followed, signed releases) is in
[SECURITY.md](../SECURITY.md#what-the-cli-guarantees), and the risk assessment behind them is in
[risk-assessment.md](risk-assessment.md). To use it securely:

- **Verify every download** before you run it: [Verify a download](../README.md#verify-a-download)
  and [docs/verifying-releases.md](verifying-releases.md). For the container image, verify it and
  pin its digest ([Container image](../README.md#container-image)).
- **Pick the right credential** ([Authenticate](../README.md#authenticate)). People sign in with
  `hodeishield login`: the token is kept in the system keychain, covers one tenant and only reads.
  Scripts, CI and servers use a tenant API key with only the read scopes they need, kept in the CI's
  secret store and passed in the environment, not on a command line. When
  `HODEISHIELD_API_KEY` is set, it is used for every call, whatever else is configured.
- **Keep the configuration file free of credentials.** It holds URLs and sign-in settings only,
  and URLs must use HTTPS; plain HTTP is accepted only for `localhost`
  ([Configure](../README.md#configure)).
- **Treat output as your organisation's data.** `--json` and `--csv` output, and the request URLs
  that `--verbose` logs, can contain identifiers and filter values from your organisation, but never
  the CLI's credential. Text from the API is cleaned of terminal control characters before
  it is printed, and CSV cells that a spreadsheet would run as a formula are prefixed with `'`
  ([CSV output](../README.md#csv-output)).
- **Behind a proxy or TLS inspection**, the CLI trusts the operating system's certificate store and
  has no option to skip certificate verification: install your organisation's CA in that store
  ([Networking](../README.md#networking-proxies-and-tls-inspection)).
- **Cut access you no longer need**: `hodeishield logout`, or revoke the CLI's access in the app
  under **Account → Application access**; revoke an API key in the app as soon as it is not needed
  or may have been exposed.

Known limitations:

- The macOS binary is not yet signed with an Apple Developer ID or notarized
  ([#50](https://github.com/Hodeitek/hodeishield-cli/issues/50)); the Sigstore signature is the
  proof that it is genuine (see
  [If macOS or Windows blocks the binary](../README.md#if-macos-or-windows-blocks-the-binary)).
- Use behind a TLS-inspecting proxy is verified on Linux only; macOS and Windows have not been
  verified yet.
- The [new-version notice](../README.md#new-version-notice) makes at most one unauthenticated
  request a day to GitHub's public API, so GitHub sees your IP address. It can be turned off (see
  [Updating](#updating)).

## Support period

From 1.0.0, each major version is supported with security fixes for five years, and the fixes ship
in the latest release of that major version. While a version is supported, security fixes stay
available even after your HodeiShield subscription ends. How this applies to the current 0.x
series, the end-of-support date of each major version and how end of support is announced are in
[SECURITY.md](../SECURITY.md#supported-versions).

## Updating

`hodeishield` never updates itself. On an interactive terminal it tells you, at most once a day,
that a newer release exists ([New-version notice](../README.md#new-version-notice)); update through
the channel you installed it with. Before you move to a new minor version while the CLI is at 0.x,
read **Changed (scripting surface)** in its release notes ([Stability](../README.md#stability)).

| Installed with | To update |
|---|---|
| Release archive | Download the new archive, verify it, and replace the binary. |
| Homebrew | `brew upgrade hodeishield` |
| Scoop | `scoop update hodeishield` |
| `.deb` / `.rpm` | Verify the newer package and install it with the same `apt install` or `dnf install` command. |
| MSI | Install the newer MSI; it upgrades the older one in place. |
| `install.sh` | Download and verify the new release's `install.sh` and run it with `--version` (and the same `--dir`, if you used one). |
| Container image | Pull the new exact-version tag (there is no `latest` tag), verify it and pin its digest. |
| `cargo install` | Run the same command with the new `--tag`. |

To turn off the new-version notice, set `HODEISHIELD_NO_UPDATE_CHECK` to any non-empty value, or
run `hodeishield config set update_check false` once for all profiles (`config unset update_check`
restores it). With either, the CLI makes no request to GitHub.

## Decommissioning

To stop using `hodeishield` on a machine and leave nothing behind:

1. **Sign out of every profile you signed in to**: `hodeishield logout`, and
   `hodeishield logout --profile <name>` for each other profile. This revokes the token at the app
   and removes it from the system keychain. If the CLI warns that the app did not confirm the
   revocation, revoke the CLI's access in the app under **Account → Application access**.
2. **Revoke the tenant API keys** the machine used, in the app, and remove them from the
   environment and secret stores that held them.
3. **Delete the configuration file and the update-check record.** `hodeishield config path` prints
   where the configuration file is; `update-check.json` is next to it. By default:

   | System | Directory |
   |---|---|
   | Linux | `~/.config/hodeishield/` (or `$XDG_CONFIG_HOME/hodeishield/`) |
   | macOS | `~/Library/Application Support/com.Hodeitek.HodeiShield/` |
   | Windows | `%APPDATA%\Hodeitek\HodeiShield\config\` |

   The files are `config.toml` and `update-check.json`. If you set `HODEISHIELD_CONFIG`, they are
   that file and `update-check.json` in its directory.
4. **Uninstall the CLI** with the channel you installed it with:

   | Installed with | To uninstall |
   |---|---|
   | Release archive | Delete the `hodeishield` binary, and any man pages you copied. |
   | Homebrew | `brew uninstall hodeishield` |
   | Scoop | `scoop uninstall hodeishield` |
   | `.deb` / `.rpm` | `sudo apt remove hodeishield` or `sudo dnf remove hodeishield` |
   | MSI | **Settings → Apps**, or `msiexec /x` ([Windows installer](../README.md#windows-installer-msi)) |
   | `install.sh` | Delete `hodeishield` from the directory it installed to (`/usr/local/bin` or `~/.local/bin`, or your `--dir`), and the `hodeishield*.1` man pages from the `share/man/man1` directory beside it (for example `/usr/local/share/man/man1`). |
   | Container image | Remove the image, for example `docker image rm ghcr.io/hodeitek/hodeishield-cli:<version>`. |
   | `cargo install` | `cargo uninstall hodeishield-cli` |

If the CLI is already gone and a sign-in was left in the keychain, revoke the access in the app
(**Account → Application access**), then delete the entry, one per profile, whose service is
`hodeishield-cli` and whose account is the profile name: on macOS with Keychain Access or
`security delete-generic-password -s hodeishield-cli -a <profile>`, on Windows in Credential Manager
(*Windows Credentials*, named `<profile>.hodeishield-cli`), and on Linux with
`secret-tool clear service hodeishield-cli username <profile>`.

## Software bill of materials

From 0.2.0, each release publishes a [CycloneDX](https://cyclonedx.org) software bill of materials
(SBOM) for each archive, `<archive-name>.cdx.json`, attached to the release with its own Sigstore
signature and listed in `SHA256SUMS`. It lists every crate compiled into that binary, with its
version, licence and package URL. The `.deb`, `.rpm` and MSI packages contain the binary of a
matching archive, which that archive's SBOM describes. The container image carries the release's
CycloneDX SBOM as a signed attestation.

The SBOM is intended for users: use it to check which components a release contains and whether any
of them has a known vulnerability. How to verify it is in
[docs/verifying-releases.md](verifying-releases.md) and
[Container image](../README.md#container-image).
