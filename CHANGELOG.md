# Changelog

Notable changes to the `hodeishield` CLI, in the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
format. The CLI follows [Semantic Versioning](https://semver.org/); its scripting surface is the
commands, `--json` output and exit codes. Each release's notes start with its section below.

## [Unreleased]

## [0.7.0] - 2026-11-01

### Changed

- The page the browser shows at the end of `hodeishield login` is now a styled page with the product mark,
  for success, denied access, a failed or mismatched response and unknown paths. It follows the system
  light or dark preference, needs no script, font or outside request, and uses the language of the
  browser when it is supported.
- `SECURITY.md` now counts the fix target for medium-severity vulnerabilities from the report, like the
  coordinated disclosure period, so it never runs past it: within 90 days of the report, extendable by
  mutual agreement. Critical and high are still counted from the first assessment.

### Fixed

- **Behaviour change for scripts:** `whoami` now exits 3, like every other command, when the API
  does not accept the credential, after printing the local details and the warning. It used to exit
  0. An API that cannot be reached or fails on its side still gives exit 0.
- The README now describes the two macOS steps to allow a blocked browser download: **Allow Anyway** in
  System Settings → Privacy & Security, then **Open Anyway** in the dialog shown on the next run
  (measured on macOS 27.0.1 with 0.6.1).

## [0.6.1] - 2026-10-29

### Fixed

- The README now says that the MSI installs for all users and needs an administrator. Run silently
  by a standard user it fails with exit code 1603 on Windows 11 and 1625 on Windows Server 2022
  (measured on 0.6.0); standard users without administrator rights should use the zip or Scoop.
- A certificate that is not trusted (unknown issuer, expired, wrong name) is no longer retried as a
  transient connection failure. The CLI makes one TLS handshake and exits with 7 and the same
  message as before, instead of making three. Refused, reset and timed-out connections and
  `502`/`503`/`504` are still retried.
  ([#245](https://github.com/Hodeitek/hodeishield-cli/issues/245))
- A `403` with `MODULE_NOT_ENTITLED` (the tenant's plan does not include the module a command
  reads, or the compliance framework is not enabled) now says so, names the scope the server
  reports, and tells the user that a tenant administrator must add the module or enable the
  framework. It still exits with 4. It used to read as a missing scope, and with no scope listed
  the generic message ended in `needs: .`, which now reads sensibly.
- That `403` now names the module the plan lacks or the compliance framework that is not enabled
  when the server says which, with a hint to add the module or enable the framework, instead of
  guessing between the two. An older server gets the same message as before.
  ([#249](https://github.com/Hodeitek/hodeishield-cli/issues/249))
- The README's DNF setup block wrote an empty `/etc/yum.repos.d/hodeishield.repo`, so `dnf install
  hodeishield` found no package. The file now gets the repository configuration.
- On Windows, `login` with its output piped (for example `hodeishield login 2>&1 | ForEach-Object
  { "$_" }`) did not return until the browser exited. The browser inherited the pipe, so the reader
  waited for it. `login` now stops the browser from inheriting the standard handles.
  ([#238](https://github.com/Hodeitek/hodeishield-cli/issues/238))

## [0.6.0] - 2026-10-26

### Added

- Signed APT and DNF repositories at `packages.hodeishield.com` for x86_64 and arm64, so `apt` and
  `dnf` install and upgrade the CLI. The README has the setup steps for Debian and Ubuntu, and for
  Fedora, RHEL, Rocky Linux and AlmaLinux, with the signing key's fingerprint. It is the only place
  that states the fingerprint and the repository configuration: check the key against it.
  ([#161](https://github.com/Hodeitek/hodeishield-cli/issues/161))

### Changed

- The generated `/v1` client follows version 2026-10-25 of the API document. `alerts list` now
  prints each alert's `updated_at` in `--json` and `--csv` output (the table is unchanged), and
  `--sort` accepts `updated_at`. The `/v1/me` answer now also carries `beta` and `user`; a `null`
  user (an API key) is still no user.
  ([#210](https://github.com/Hodeitek/hodeishield-cli/issues/210))

### Fixed

- `whoami` works when the API leaves out the user's `email`, which it does for a token without the
  `email` scope: it shows the name, or the id, and no longer fails to read the answer. Browser
  sign-in now also asks for the `email` scope, but only when the app lists it among its supported
  scopes. The generated client follows version 2026-10-26 of the API document.
  ([#217](https://github.com/Hodeitek/hodeishield-cli/issues/217))
- `alerts list` no longer depends on `page`, `total` and `total_pages` in the answer, which the API
  now treats as optional. When they are missing, `--all` stops at a page with a null `next_cursor`
  or fewer alerts than the page size, and the `Page N of M` line is not printed.
  ([#210](https://github.com/Hodeitek/hodeishield-cli/issues/210))

### Security

- ctutils is updated from 0.4.3 to 0.4.4 and tokio from 1.53.2 to 1.53.3. They fix RUSTSEC-2026-0385
  (ctutils mask generation and `u128` comparisons were not constant-time on some platforms) and
  RUSTSEC-2026-0386 (`AsyncFd::new` and related constructors in tokio violate I/O safety). The CLI
  does not call either affected API directly; both crates are dependencies of its dependencies.

## [0.5.1] - 2026-10-18

### Changed

- When the system has no CA certificates, the error for a request that cannot start or reach the API
  now suggests installing the system CA certificates package (for example `ca-certificates`). The
  HTTP client reports that case only as "No CA certificates were loaded from the system".
  ([#196](https://github.com/Hodeitek/hodeishield-cli/issues/196))
- `--help` no longer prints the values of `HODEISHIELD_API_URL` and `HODEISHIELD_PROFILE` when they
  are set in the environment.
- The `login` help, the session notice and the README name the screen where an app's access is
  revoked "Account → Applications", as the web app does, and the README and `config set --help`
  match the code on `login --no-browser` and the configuration keys.
  ([#199](https://github.com/Hodeitek/hodeishield-cli/issues/199))
- CI now runs the proxy and TLS inspection test on macOS and Windows as well as Linux.

### Fixed

- Usage errors no longer list `--api-url` or `--profile` in the `Usage:` line when only
  `HODEISHIELD_API_URL` or `HODEISHIELD_PROFILE` sets them. The variables still work the same and
  `--help` still names them.
  ([#201](https://github.com/Hodeitek/hodeishield-cli/issues/201))

### Documentation

- The README lists the Linux prerequisites to install and to verify a download, gives a checksum
  command that BusyBox also runs, and has Windows steps to check a download and to get Scoop and
  cosign.
  ([#195](https://github.com/Hodeitek/hodeishield-cli/issues/195))
- The README says how to uninstall the archive and `install.sh` installs, in which order (remove the
  settings before the binary), what an uninstall leaves behind on Windows, how to remove the zip
  and how to check the MSI.
  ([#197](https://github.com/Hodeitek/hodeishield-cli/issues/197))
- The Quick start points servers and CI from the interactive sign-in to the tenant API key.
  ([#198](https://github.com/Hodeitek/hodeishield-cli/issues/198))
- The README says that `login` and `logout` exit with code 1 when the system keychain cannot be
  reached.
  ([#200](https://github.com/Hodeitek/hodeishield-cli/issues/200))
- The Install section links to the steps for a binary that macOS or Windows blocks, and the Windows
  steps (`Unblock-File`, SmartScreen's "More info → Run anyway") apply to every version.
  ([#16](https://github.com/Hodeitek/hodeishield-cli/issues/16))
- The README says that two profiles signed in as the same user, to the same tenant, with the same
  flow share one sign-in, so logging out of either one signs out both.

## [0.5.0] - 2026-10-15

### Added

- An opt-in plain-text token store, for machines that have no system keychain (an SSH or jump host,
  WSL without a desktop). Set `HODEISHIELD_TOKEN_STORE=plaintext-file`, or the global setting
  `hodeishield config set token_store plaintext-file`, and `login --device` keeps the session in a
  file only your user can read, one per profile, in the platform's state directory
  (`$XDG_STATE_HOME/hodeishield/sessions/` on Linux). The keychain stays the default, nothing ever
  falls back from one store to the other, and the file store is not available on Windows yet. Every
  read and write refuses a file or directory that is a symbolic link, belongs to another user or is
  open to group or others (exit code 3 for commands that need a credential, 1 for `login` and
  `logout`); files are replaced atomically with mode 600. `logout` revokes the tokens
  and deletes the file. The README has a new section, "Servers, containers and remote sessions",
  with the trade-off and the advice for containers and CI (a tenant API key); ADR 0001 records the
  decision. A copy of the file stays usable at most 90 days from the sign-in, the limit the
  service sets. A configuration file that contains `token_store` is refused by older CLIs.
  ([#39](https://github.com/Hodeitek/hodeishield-cli/issues/39))
- `reports list`, `reports get` and `reports download`: the reports generated for the tenant, and
  their files. `reports list` filters by `--type`, `--status` and `--since` and takes the usual
  paging, `--json` and `--csv`; `reports get` shows the formats a report can be downloaded in.
  `reports download` saves a completed report as PDF or XLSX (`--format`, `--locale`) in the current
  directory under the name the API suggests, reduced to a plain stem with the extension of the
  format, or at `--output <PATH>`;
  `--output -` writes it to standard output when that is not a terminal. An existing file is only
  replaced with `--force`, a file is never left half written, and on Unix it is readable only by you. A report that is still being
  generated, failed, has no file in that format or is too large fails with a message that says so.
  ([#55](https://github.com/Hodeitek/hodeishield-cli/issues/55))
- A `security.txt` (RFC 9116) for this repository, at `.well-known/security.txt` on `main`, with the
  private reporting link, the security address, the preferred languages and the link to
  `SECURITY.md`; `SECURITY.md` points to it. A weekly check validates the file and opens an issue
  when it is invalid or has less than 60 days left before its expiry date.
  ([#125](https://github.com/Hodeitek/hodeishield-cli/issues/125))
- The release workflow can sign and notarize the macOS binaries with a Developer ID: the universal
  binary is signed with the hardened runtime and notarized, and a `.pkg` installer is signed,
  notarized and stapled. A new on-demand workflow, "macOS signing check", tests the stored signing
  secrets without a release. Until the signing identity is stored, releases say in their run summary
  that macOS signing was skipped.
  ([#50](https://github.com/Hodeitek/hodeishield-cli/issues/50))

### Changed

- `risks list --domain` and `--status` and `compliance controls --status` now list the values the
  API publishes for them in `--help`. A value that is not listed gets a warning on standard error
  (with a suggestion when only the case differs) and is still sent exactly as typed. The vendors
  `--category` filter stays free text: the API keeps no list of categories.
  ([#145](https://github.com/Hodeitek/hodeishield-cli/issues/145))
- The generated `/v1` client follows version 2026-10-19 of the API document, which adds `GET /v1/me`
  and the reports operations, including the download of a report file. `hodeishield login` now also
  asks for `reports:read` when the app offers it.
- `whoami` shows the tenant the credential reads (name and id), its organisation and, for a key, its
  scopes; for a portfolio key, the MSSP and the number of client tenants. It reads them from the
  new `GET /v1/me`, so it now makes one API call. `--json` gains the `tenant`, `organization`,
  `portfolio` and `credential_scopes` fields, null when the API cannot be read; the exit code does
  not depend on that call.
  ([#48](https://github.com/Hodeitek/hodeishield-cli/issues/48))
- `whoami` shows the signed-in user (`Name <email>`, in the `User` line and the `--json` `user`
  string) from `GET /v1/me` when the API provides it for a sign-in, with no extra call. The
  authorization server's userinfo endpoint stays as the fallback; a key still shows no user, and
  nothing changes while the API does not send one.
  ([#182](https://github.com/Hodeitek/hodeishield-cli/issues/182))

### Fixed

- The README installs with Homebrew by the full name, `brew install hodeitek/hodeishield/hodeishield`,
  which adds the tap and trusts only this formula. Homebrew now refuses a formula from a tap that is
  not trusted, so the earlier `brew tap` then `brew install hodeishield` failed. The README also says
  how to trust the formula when the tap was added before.
  ([#179](https://github.com/Hodeitek/hodeishield-cli/issues/179))
- The README explains the System Settings route to open a blocked macOS binary, that unpacking with
  `tar` in Terminal keeps the block, and that the dialog follows the system language.
  ([#16](https://github.com/Hodeitek/hodeishield-cli/issues/16))

## [0.4.4] - 2026-10-15

### Security

- rustls, the TLS library behind every connection the CLI makes, is updated from 0.23.45 to
  0.23.46. It fixes RUSTSEC-2026-0346 (`Debug` output of client session values exposed TLS
  secrets), RUSTSEC-2026-0347 (buffered data sent to the outer server after an ECH rejection),
  RUSTSEC-2026-0348 (Brotli certificate decompression could allocate up to 1 GiB before
  authentication) and RUSTSEC-2026-0349 (an unauthenticated ServerHello could downgrade later
  connections to classical key exchange). Releases up to 0.4.3 include the affected version.

## [0.4.3] - 2026-10-14

### Added

- `docs/technical-documentation.md`: the index of the technical documentation of the Cyber
  Resilience Act (Annex VII), with the product category, the conformity route, who signs the
  declaration, how the CE marking is shown for software and how the documentation is kept; and
  `docs/declaration-of-conformity.md`, the template of the EU declaration of conformity. The
  user information now gives the address of the declaration.
  ([#129](https://github.com/Hodeitek/hodeishield-cli/issues/129))
- `docs/third-party-components.md`: the criteria for adding a dependency and who reviews it, how
  the dependency checks fit together, what is done when a dependency has a vulnerability, and how
  it is reported to the component's maintainers with any fix. SECURITY.md, CONTRIBUTING.md and the
  pull request template point to it.
  ([#130](https://github.com/Hodeitek/hodeishield-cli/issues/130))
- The Linux binaries can be rebuilt from the release tag with the same bytes:
  `packaging/build/build.sh` builds them in a container image pinned by digest, with Debian packages
  from a fixed snapshot, and the release builds them the same way. `docs/verifying-releases.md`
  describes the rebuild, and a workflow repeats it for every published release.
  ([#43](https://github.com/Hodeitek/hodeishield-cli/issues/43))

### Changed

- A release is no longer signed or published while a security advisory is open for its tagged
  commit: the release workflow checks it with `cargo deny` and `cargo audit` against the RustSec
  advisory database, and the release notes end with the result. An advisory can only be accepted
  in `deny.toml` with a written reason and a review date, which CI checks; `CONTRIBUTING.md`
  ("Known vulnerabilities at release") has the rule.
  ([#121](https://github.com/Hodeitek/hodeishield-cli/issues/121))

## [0.4.2] - 2026-10-12

### Added

- Every release archive, `.deb`, `.rpm` and the MSI now include the user information
  (`docs/user-information.md`) as `USER-INFORMATION.md`: next to the binary in the archives, in
  `/usr/share/doc/hodeishield/` from the `.deb` and `.rpm`, in `%ProgramFiles%\HodeiShield CLI`
  from the MSI, and in the documentation folder of the Homebrew formula. The release workflow fails
  if an archive or package lacks it. The container image carries the binary and licence files only;
  the README says where its user information is.
  ([#133](https://github.com/Hodeitek/hodeishield-cli/issues/133))
- `docs/risk-assessment.md`: the cybersecurity risk assessment. It lists what the CLI protects, the
  threats considered and the controls. It says how each security requirement of the Cyber Resilience
  Act is met or why it does not apply, and why the CLI does not update itself or keep an activity
  log. ([#122](https://github.com/Hodeitek/hodeishield-cli/issues/122),
  [#123](https://github.com/Hodeitek/hodeishield-cli/issues/123))

### Changed

- `docs/release-signing.md` lists the credentials and identities that sign releases (Sigstore, SLSA
  provenance, the container image, and Authenticode through Azure Artifact Signing) and who may
  change them, and describes what the maintainers do if the Windows certificate profile or the
  release workflow is compromised. `docs/verifying-releases.md` now says how to recognise a release
  published after such a change and how to check the Authenticode certificate profile. `SECURITY.md`
  no longer says that no long-lived signing key exists at all, and points to the published
  `security.txt` ([#126](https://github.com/Hodeitek/hodeishield-cli/issues/126),
  [#125](https://github.com/Hodeitek/hodeishield-cli/issues/125)).
- `docs/release-signing.md` also says who controls the Azure access used for Windows signing, with
  its known gaps, and describes a weekly check that compares the release runs, the published files,
  their entries in the Rekor transparency log and the container image signatures, and opens an issue
  when something does not match ([#126](https://github.com/Hodeitek/hodeishield-cli/issues/126),
  [#152](https://github.com/Hodeitek/hodeishield-cli/issues/152)).

### Fixed

- Counts on standard error now use the singular for one item: "1 vendor across 2 client tenants",
  "1 vendor." after `--all`, and "Skipping 1 inactive client tenant".
  ([#135](https://github.com/Hodeitek/hodeishield-cli/issues/135))
- An API error message that already ends with a full stop no longer gets a second one ("The API
  rejected the request: … ."). ([#136](https://github.com/Hodeitek/hodeishield-cli/issues/136))
- `logout` now removes a sign-in that the keychain returns in a form the CLI cannot read, and says
  that nothing was revoked at the app. Before, it failed with the same "unreadable" error whose hint
  told the user to run `logout`. ([#154](https://github.com/Hodeitek/hodeishield-cli/issues/154))

## [0.4.1] - 2026-10-12

### Fixed

- `install.sh` now checks the release's signature with cosign v2 (2.4 or newer) as well as v3. With
  cosign v2 it stopped with "the Sigstore signature does not verify" although the release was
  genuine: the signatures are Sigstore bundles that cosign v2 reads only with `--new-bundle-format`,
  which the script now adds. With an older cosign it names the version it needs instead. The README
  and `docs/verifying-releases.md` now say which cosign versions work, and what to add with v2.
  ([#141](https://github.com/Hodeitek/hodeishield-cli/issues/141))

## [0.4.0] - 2026-10-12

### Added

- Each release now includes a Windows on Arm build, `hodeishield-<version>-aarch64-pc-windows-msvc.zip`.
  It is built natively on a Windows on Arm runner, its `hodeishield.exe` is signed with Authenticode
  like the x64 one and checked to need no Visual C++ runtime, and the archive is listed in
  `SHA256SUMS`, signed with Sigstore, covered by the build provenance and has its own SBOM. The
  Scoop manifest offers it to Windows on Arm; the MSI and winget package remain x64 only. CI now
  runs the tests, clippy and the import check on Windows on Arm too.
  ([#37](https://github.com/Hodeitek/hodeishield-cli/issues/37))

- On an interactive terminal, the CLI now tells you in one line on standard error when a newer
  release exists. It asks GitHub's public releases API (no credential or identifier is sent) at most
  once a day, stays silent with `--json`, `--csv`, `completions`, when standard error is not a
  terminal and when `CI` is set, and never changes a command's output or exit code. Turn it off with
  `HODEISHIELD_NO_UPDATE_CHECK=1` or `hodeishield config set update_check false`; the README's
  "New-version notice" section lists exactly what is sent.
  ([#38](https://github.com/Hodeitek/hodeishield-cli/issues/38))
- A container image, `ghcr.io/hodeitek/hodeishield-cli`, for `linux/amd64` and `linux/arm64`, built
  for each stable release: the release's own binary on a distroless base, running as a non-root
  user, tagged with the exact version only. It is signed by digest with Sigstore and carries the
  release's SBOM as a signed attestation. ([#36](https://github.com/Hodeitek/hodeishield-cli/issues/36))
- Several client tenants with one portfolio key. `hodeishield tenants list` lists the client
  tenants the key may read. The key is created by an organisation administrator of an active MSSP
  organisation and goes in `HODEISHIELD_API_KEY`. The global `--tenant <slug|id>` selects one client
  for any read command, including `get` and `compliance posture`, and prints the line
  `Client tenant: <slug> (<id>)` on standard error. `--all-tenants` reads every client on a `list` command and adds
  `tenant_id`, `tenant_slug` and `tenant_name` to each row in `--json` and `--csv` (a `TENANT`
  column in the table). An unknown client fails with exit code 5, before any data is read. Without
  these options nothing changes. `--all-tenants` asks one client at a time and skips clients that
  are inactive or whose licence is not in force, with a note on standard error; the command still
  exits 0 when only inactive clients are skipped. A client whose licence status the CLI does not
  know is not read and is named on standard error. A client that fails when it is read because its
  licence is not in force (exit code 8) or it is not found (exit code 5) is also named and skipped.
  In both cases the other clients' data is printed and the command then exits non-zero (with the
  code of the first client that failed, or 1 for an unknown licence status), so a script never takes
  a partial result for a complete one. Any other failure stops the run before anything is printed,
  for example exit code 6 (naming the limit) when a rate limit is exhausted. Against an API without
  portfolio access the commands fail with exit code 7. The README has a new "Several tenants (MSSP)"
  section. ([#54](https://github.com/Hodeitek/hodeishield-cli/issues/54),
  [#45](https://github.com/Hodeitek/hodeishield-cli/issues/45))

### Changed (scripting surface)

- In a session where the system keychain cannot be reached (a Windows SSH or other network logon,
  or a Secret Service on Linux that is locked or does not answer) and no API key is set, commands
  such as `whoami` no longer fail with a raw platform error and exit code 1. They now say that the
  system keychain is not available in this session, suggest `HODEISHIELD_API_KEY` for remote and
  automated sessions, and exit with 3, the code for "not authenticated". With the key set, nothing
  changes. What to do: treat exit 3 as "this session cannot keep a login, use an API key", and do
  not rely on exit 1 for this case. ([#111](https://github.com/Hodeitek/hodeishield-cli/issues/111))
- A failed command no longer exits 0 when the API's error message happens to contain the words
  "Broken pipe". The CLI now treats a failure as a closed output pipe (`hodeishield ... | head -1`,
  which still exits 0 silently) only when writing to standard output fails with that I/O error,
  never because of the text of a message. What to do: a script that relied on exit 0 after such a
  failed command must now handle the documented non-zero code (see "Exit codes" in the README).
  ([#105](https://github.com/Hodeitek/hodeishield-cli/issues/105))
- A broken pipe from anything other than standard output (a network connection, a file, the
  configuration being saved) no longer ends a command with exit code 0 and no message. Only a write
  to standard output that fails because the reader went away is treated as a closed pipe; any other
  broken pipe is reported as an error with a non-zero exit code. What to do: as above, handle the
  non-zero code instead of expecting exit 0. ([#105](https://github.com/Hodeitek/hodeishield-cli/issues/105))

### Changed

- The README documents more of how to use and depend on the CLI: the interface stability policy,
  with what a script can rely on ([#58](https://github.com/Hodeitek/hodeishield-cli/issues/58), [#92](https://github.com/Hodeitek/hodeishield-cli/pull/92)); using the CLI behind a proxy or
  TLS inspection ([#25](https://github.com/Hodeitek/hodeishield-cli/issues/25), [#89](https://github.com/Hodeitek/hodeishield-cli/pull/89)); the beta programme and its terms
  ([#52](https://github.com/Hodeitek/hodeishield-cli/issues/52), [#90](https://github.com/Hodeitek/hodeishield-cli/pull/90)); defining a profile before signing in to it, and waiting for
  `msiexec` in a silent install ([#87](https://github.com/Hodeitek/hodeishield-cli/pull/87)).
  `SECURITY.md` now says what happens after a vulnerability report, where a notice about an affected
  release appears (the README has an empty place for it), and how advisories are published, from
  a template kept in `docs/` ([#120](https://github.com/Hodeitek/hodeishield-cli/issues/120)).
  `SECURITY.md` now states the support period (from 1.0.0, five years of security fixes per major
  version; until then, the latest 0.x release), and `docs/user-information.md` gathers the contact
  details, secure use, updating, removal and where the SBOM is published
  ([#127](https://github.com/Hodeitek/hodeishield-cli/issues/127),
  [#128](https://github.com/Hodeitek/hodeishield-cli/issues/128)).
- The alerts `--severity` filter now shows in `--help` the values the API lists (`critical`, `high`,
  `medium`, `low`, `info`), and warns on standard error about a value the API does not list or has
  deprecated. For the deprecated values (`critico`, `alto`, `medio`, `bajo`, accepted until
  2027-01-14) the warning names the value to use instead. The value is still sent as typed, and exit
  codes do not change. The CLI now follows version 2026-10-16 of the API document.
  ([#53](https://github.com/Hodeitek/hodeishield-cli/issues/53))
- Errors that involve a client tenant now say so and what to do. An unknown client tenant (404
  `TENANT_NOT_FOUND`) points to `hodeishield tenants list`; a portfolio key rejected for a missing
  scope points to an organisation administrator; a rate limit names whether it is the key's, the
  organisation's or the client tenant's own, and says whether other clients are affected; a
  credential that covers several clients without `--tenant` or `--all-tenants` is told to pick one;
  and `--tenant` with a credential for one tenant only is told to leave it out. Messages and
  hints go to standard error; exit codes do not change. ([#54](https://github.com/Hodeitek/hodeishield-cli/issues/54),
  [#45](https://github.com/Hodeitek/hodeishield-cli/issues/45))

### Fixed

- Terminal output cleaning now also replaces the line and paragraph separators (U+2028, U+2029),
  the deprecated format characters U+206A to U+206F and the tag characters and variation selectors supplement
  (U+E0000 to U+E0FFF), which display differently from what they contain. This applies to tables,
  detail views, CSV and the escaping of `--json` output. ([#106](https://github.com/Hodeitek/hodeishield-cli/issues/106))
- CSV output now also defuses a field whose first character after any leading whitespace is `=`,
  `+`, `-` or `@`, or one of their full-width forms (for example `" =1+1"`, or a no-break space
  before `=cmd`). It decides on the text as it is written, because some spreadsheet applications
  trim the whitespace before evaluating the cell. Numbers are still written as they are.
  ([#106](https://github.com/Hodeitek/hodeishield-cli/issues/106))
- `install.sh` now looks up the latest release over HTTPS only, with TLS 1.2 or newer, as the
  download already did, so a redirect cannot lead that lookup to another protocol.
  ([#106](https://github.com/Hodeitek/hodeishield-cli/issues/106))
- `hodeishield login` now checks that the system keychain can keep a session before it opens the
  browser or shows a device code, and stops there with the usual pointer to API keys. If saving the
  session still fails after the app has issued tokens, the CLI revokes the refresh token and then
  the access token, says so on standard error and exits non-zero, instead of leaving an active
  grant that nothing holds. The hint for a missing keychain now names the one for your system
  (Secret Service, the Keychain prompt, or Credential Manager). ([#101](https://github.com/Hodeitek/hodeishield-cli/issues/101))
- A stalled or slow local connection can no longer keep the browser sign-in listener busy past its
  timeout. Each connection now has a total time limit for its request, and no read waits beyond the
  overall sign-in deadline, and the deadline is checked before every connection is accepted, so a
  process sending a byte every few seconds, or connecting over and over, cannot block the real
  redirect or stop `hodeishield login` from timing out. A client that resets its connection before
  it is accepted no longer ends the sign-in. ([#104](https://github.com/Hodeitek/hodeishield-cli/issues/104))

## [0.3.1] - 2026-10-10

### Fixed

- The Windows executable no longer needs the Visual C++ Redistributable; it failed to start on systems
  without it ([#110](https://github.com/Hodeitek/hodeishield-cli/issues/110)).

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

[Unreleased]: https://github.com/Hodeitek/hodeishield-cli/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/Hodeitek/hodeishield-cli/compare/v0.6.1...v0.7.0
[0.6.1]: https://github.com/Hodeitek/hodeishield-cli/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/Hodeitek/hodeishield-cli/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/Hodeitek/hodeishield-cli/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/Hodeitek/hodeishield-cli/compare/v0.4.4...v0.5.0
[0.4.4]: https://github.com/Hodeitek/hodeishield-cli/compare/v0.4.3...v0.4.4
[0.4.3]: https://github.com/Hodeitek/hodeishield-cli/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/Hodeitek/hodeishield-cli/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/Hodeitek/hodeishield-cli/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/Hodeitek/hodeishield-cli/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/Hodeitek/hodeishield-cli/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/Hodeitek/hodeishield-cli/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Hodeitek/hodeishield-cli/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/Hodeitek/hodeishield-cli/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Hodeitek/hodeishield-cli/releases/tag/v0.1.0
