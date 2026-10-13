# Cybersecurity risk assessment

This document is the cybersecurity risk assessment of `hodeishield` that Article 13(2) to (4) of the
Cyber Resilience Act, [Regulation (EU) 2024/2847](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng),
asks for. It lists the assets, the threats considered and the controls, says how each requirement of
Annex I, Part I and Part II is met or why it does not apply, and records the decisions behind them.
It describes version 0.4.1 and the code on the `dev` branch at the date of the first review (see
[Review](#review)). Every statement about the product names the file or document that backs it, so
that a reader can check it.

For what users need to know to use the CLI securely, see
[user-information.md](user-information.md); for how to report a vulnerability, see
[SECURITY.md](../SECURITY.md).

## Intended purpose and conditions of use

`hodeishield` is a read-only command-line client for the public `/v1` API of HodeiShield. It reads
one organisation's third-party inventory, alerts, risk register, compliance posture, evidence and
endpoint agents ([user-information.md](user-information.md#intended-purpose)). It runs as a short-lived
process on the user's own machine, started by a person or a script, and has no server part, daemon
or plug-in interface.

- **Credentials.** A person signs in with `hodeishield login`, which gives a token for one tenant;
  scripts use a tenant API key from `HODEISHIELD_API_KEY`
  ([README.md](../README.md#authenticate)).
- **Operating environments.** Linux, macOS and Windows workstations, servers and CI runners, and a
  container image for pipelines ([README.md](../README.md#install)). The user's account on the
  machine, the operating system's keychain and its certificate store are trusted; a machine whose
  user account is already compromised is out of scope (see [Residual risks](#residual-risks)).
- **Expected time in use.** The support period is set in
  [SECURITY.md](../SECURITY.md#supported-versions): five years per major version from 1.0.0, and the
  latest release while the 0.x series is current.

## Assets

| Asset | Where it is | Why it matters |
|---|---|---|
| Sign-in tokens (access and refresh) | The system keychain, one entry per profile (`crates/hodeishield-cli/src/auth/store.rs`, `Keychain`) | They read one tenant's supply-chain risk data until revoked or expired. The refresh token lives longest |
| Tenant API key | The `HODEISHIELD_API_KEY` environment variable, never stored by the CLI (`auth/mod.rs`, `api_key_from_env`) | Long-lived; reads whatever its scopes allow |
| Sign-in secrets in transit | Memory only: PKCE verifier, `state`, authorization code, device code (`auth/oauth.rs`, `auth/loopback.rs`) | A stolen code or verifier could be redeemed for a token during the few minutes a sign-in lasts |
| Configuration file | `config.toml` in the user's configuration directory (`config.rs`) | URLs and sign-in settings. A changed URL could redirect sign-in or requests |
| Update-check record | `update-check.json` next to the configuration file (`update_check.rs`) | A time and a version number; no personal data |
| Command output | Standard output, as table, JSON or CSV | The organisation's data, in the user's hands once printed |
| Source repository and release workflow | GitHub: `main`, `.github/workflows/release.yml`, the `release tags` ruleset, the `release-signing` and `packaging` environments ([release-signing.md](release-signing.md#who-may-change-them)) | Whoever controls them controls what is signed as genuine |
| Release artefacts | Archives, `.deb`, `.rpm`, MSI, container image, `SHA256SUMS`, SBOMs, provenance, with their signatures ([verifying-releases.md](verifying-releases.md)) | Users run them with their credentials |
| Signing identities | The Sigstore workflow identity, the SLSA generator identity, the Authenticode certificate profile ([release-signing.md](release-signing.md#signatures-and-identities)) | They are what users verify |
| `install.sh` | Published with each release and signed like the archives (`install.sh`) | It puts a binary on the machine and runs with the user's rights |
| Dependencies | `Cargo.lock`, GitHub Actions, build tools pinned in the workflows (`CONTRIBUTING.md`, "Dependency updates") | They are compiled into the binary or run in the release pipeline |

## Threats and controls

| # | Threat | Controls |
|---|---|---|
| T1 | A token or key is read from disk, a backup or a repository | Tokens are written only to the system keychain; there is no file fallback (`auth/store.rs`, module comment). The configuration file holds no credential and is created with mode 0600 on Unix (`config.rs`, `write_private`). The API key is read from the environment and never stored. Secrets are held as `SecretString`, and a test checks that `Debug` output never shows tokens (`auth/store.rs`, test `debug_never_shows_tokens`) |
| T2 | A credential is sent to the wrong host: plain HTTP, a redirect, a crafted URL, a changed profile | Base URLs must be HTTPS and carry no user name or password; plain HTTP is accepted only for a loopback host (`config.rs`, `parse_url`; `hodeishield-api/src/client.rs`, `check_base_url`). The client refuses to follow redirects and is built with `https_only` (`client.rs`, `build`); the sign-in client does the same (`auth/oauth.rs`, `http_client`). A sign-in token is sent only to the API it was obtained for, and only the app that issued it is used to refresh or revoke it (`auth/mod.rs`, `credential_with`, `current_token`) |
| T3 | An attacker on the network reads or changes traffic | TLS with the operating system's certificate store; no option to skip verification (README, "Networking"). Loopback traffic never uses a proxy (`client.rs`, `build`) |
| T4 | The API or the app sends hostile content: terminal escape sequences, spreadsheet formulas, oversized bodies | Text from the server is cleaned of control, invisible and bidirectional characters before it is printed; JSON output escapes them; CSV cells that a spreadsheet would run are prefixed with `'` (`output.rs`, `clean`, `print_json`, `defuse`). Bodies larger than 8 MiB are refused (`client.rs`, `MAX_RESPONSE_BYTES`) |
| T5 | Another local program or a web page abuses the sign-in listener | The listener binds `127.0.0.1` on a port chosen by the system, answers only `/callback`, requires the `state` of this sign-in and, when the server sends it, a matching `iss`, serves one valid callback and stops, and bounds how long a connection and the whole wait may last (`auth/loopback.rs`). The flow uses PKCE with S256 and refuses an app that does not support it (`auth/oauth.rs`). `login --device` avoids the listener |
| T6 | A script or a repository leaks the API key | The key is read from the environment, never from a flag, so it is not on a command line; the CLI never prints it, and `--verbose` logs no header ([README.md](../README.md#authenticate), `client.rs`, `RequestEvent`). [user-information.md](user-information.md#security-properties-and-secure-use) tells users to keep it in a secret store and to give it only the read scopes needed |
| T7 | The CLI changes data in the user's organisation | The API client has only `GET` (`client.rs`; "Only `GET` requests exist in this client"). The only other requests are the sign-in, token refresh and revocation calls to the app's OAuth endpoints (`auth/oauth.rs`) and the update check |
| T8 | A downloaded file is not the one the maintainers built | Releases carry `SHA256SUMS`, Sigstore signatures and SLSA provenance, and Windows files an Authenticode signature ([verifying-releases.md](verifying-releases.md)). `install.sh` checks the checksum always and the Sigstore signature unless `--no-verify` is given (`install.sh`). The container image is signed by digest and carries a signed SBOM ([README.md](../README.md#container-image)) |
| T9 | The release pipeline or a signing identity is compromised | `main` accepts changes only through pull requests with passing checks and signed commits; `v*` tags are restricted to the release team; signing jobs wait for a reviewer in the `release-signing` environment; Windows keys never leave the signing service; Sigstore uses no stored key ([release-signing.md](release-signing.md#who-may-change-them)). The response is described in [release-signing.md](release-signing.md#if-the-windows-signing-is-compromised) and [the workflow identity section](release-signing.md#if-the-release-workflow-identity-is-compromised). Workflows are checked by actionlint, zizmor and Scorecard, and actions are pinned by commit. A weekly check compares the release runs, the published files, their Rekor entries and the container image signatures ([release-signing.md](release-signing.md#weekly-release-integrity-check)) |
| T10 | A dependency is vulnerable or malicious | `Cargo.lock` is committed and builds use `--locked` (`.github/workflows/release.yml`). `cargo deny` (licences, sources, wildcards; `deny.toml`) and `cargo audit` run on every pull request; OSV-Scanner and CodeQL run on every change and weekly; Dependabot proposes updates only for versions at least seven days old and never major ones (`.github/dependabot.yml`; [CONTRIBUTING.md](../CONTRIBUTING.md#security-testing)). A new dependency is reviewed against written criteria ([third-party-components.md](third-party-components.md#adding-a-dependency)) |
| T11 | `install.sh` is altered or piped blindly into a shell | It is signed like the archives; the README tells users to download, verify and read it before running it, and not to pipe it ([README.md](../README.md#install-script-linux-and-macos)). It uses HTTPS with TLS 1.2 or later for every download (`install.sh`) |
| T12 | Access stays alive after a person or machine no longer needs it | `logout` revokes the token at the app and deletes it; access can also be revoked in the app; [Decommissioning](user-information.md#decommissioning) covers the machine (`commands/session.rs`, `logout_with`) |
| T13 | A sign-in is lost to an unavailable keychain, or kept without a safe store | `login` checks that the keychain is usable before it opens the browser or shows a code, and refuses otherwise (`commands/session.rs`, `login_with`; `auth/store.rs`, `check_available`). The error points to the tenant API key |

## Token store

On this branch the system keychain is the only store of sign-in tokens: macOS Keychain, Windows
Credential Manager, or the Secret Service on Linux and the BSDs (`auth/store.rs`, `native_store`).
There is no file, encrypted file, kernel keyring or credential-helper fallback in the code, and no
environment variable that changes this. The only other implementation of the `TokenStore` trait is a
store used by the tests (`MemoryStore`, compiled only for tests). A machine without a keychain uses a
tenant API key instead.

[Decision record 0001](decisions/0001-sign-in-without-a-keychain.md) discusses other stores. Its
status is Proposed: nothing in it is decided or implemented. Adding any store of tokens, or a new
credential source, changes the threat model and triggers a review of this document (see
[Review](#review)).

## Requirements of Annex I, Part I

Point (1) asks for an appropriate level of cybersecurity based on the risks. Points (2)(a) to (m)
apply "on the basis of the cybersecurity risk assessment and where applicable". The text of each
point is paraphrased from the Official Journal.

| Point | Requirement | How it is met, or why it does not apply |
|---|---|---|
| (1) | Appropriate level of cybersecurity based on the risks | This document: assets, threats and controls above. The design is read-only and local, which removes whole classes of risk (T7), and the controls for the remaining ones are listed in T1 to T13 |
| (2)(a) | No known exploitable vulnerabilities when made available | Dependencies are checked against RustSec and OSV on every pull request and weekly, and CodeQL analyses the code (T10; [CONTRIBUTING.md](../CONTRIBUTING.md#security-testing)). A failed scheduled run is looked at before the next release. Releases are built from `Cargo.lock` with `--locked`. The release workflow checks the tagged commit against the advisory database and neither signs nor publishes while an advisory is unaddressed; an advisory is accepted only with a written reason and a review date ([CONTRIBUTING.md](../CONTRIBUTING.md#known-vulnerabilities-at-release)) |
| (2)(b) | Secure by default configuration; possibility to reset to the original state | No configuration is needed to be safe: HTTPS only, no redirects, read-only, tokens only in the keychain, update check off in scripts and CI (Decisions below). Resetting is described in [Decommissioning](user-information.md#decommissioning), which removes tokens, the configuration file and the update-check record |
| (2)(c) | Vulnerabilities can be fixed by security updates, with automatic updates on by default and an opt-out, notification, and the option to postpone | Security updates are released through the normal release process ([SECURITY.md](../SECURITY.md#severity-and-fix-targets)). Automatic updates are not provided, by decision (see [No automatic updates](#no-automatic-updates)). Notification is: the new-version notice, security notices and release notes marked "Security" ([SECURITY.md](../SECURITY.md#security-notices)). Postponing needs no mechanism, because nothing is installed without the user |
| (2)(d) | Protection from unauthorised access; report on it | The CLI has no local accounts or privileged functions. Access to data is controlled by the service: every API call needs a credential, a sign-in token covers one tenant and only reads, and a key has scopes ([README.md](../README.md#authenticate)). In the CLI, the credential is bound to its API and app (T2), the sign-in is protected (T5) and access can be revoked (T12). A rejected or missing credential is reported with exit code 3 or 4 and a request id ([README.md](../README.md#exit-codes)). Records of access to the data are kept by the service, not by the CLI (see [Security logging](#security-logging)) |
| (2)(e) | Confidentiality of stored, transmitted or processed data | In transit: TLS only, no bypass (T2, T3). At rest: the only secrets are in the keychain, which protects them with the user's login (T1); the configuration file has none. Processed: secrets are held as `SecretString` and not printed or logged. Output is the user's own data and goes where they direct it |
| (2)(f) | Integrity of data, commands, programs and configuration against unauthorised change; report on corruptions | Programs: signatures, checksums and provenance (T8). Configuration: `config.toml` is parsed strictly and an invalid file is refused with its path (`config.rs`, `deny_unknown_fields`, `load`). Stored sign-in: an unreadable keychain entry is reported with a hint to sign in again, not used (`auth/store.rs`, `load`). Data from the service is not trusted for display (T4). Commands cannot be injected: the CLI runs no shell and starts no program except the user's browser for sign-in (`commands/session.rs`, `webbrowser::open`) |
| (2)(g) | Process only the data that is adequate, relevant and limited to what is necessary | See [Data minimisation](#data-minimisation) |
| (2)(h) | Availability of essential and basic functions, also after an incident; resilience against denial of service | The CLI is not a service and has no listener except during sign-in. Requests have timeouts (30 s, 10 s to connect), reads are bounded (T4) and a failure of the update check never changes a command's result (`update_check.rs`). If the keychain is unavailable, the API key path still works (T13). Resilience of the service itself is the service's concern |
| (2)(i) | Minimise the impact on the availability of other services and networks | Retries are limited to two for rate limits and two for transient failures, wait for the server's `Retry-After` only up to 60 s, and use jittered backoff capped at 8 s (`client.rs`, `backoff`, defaults in `ClientBuilder`). Only `GET` requests are sent. The update check is at most one request a day with a 2 s limit (`update_check.rs`) |
| (2)(j) | Limit attack surfaces, including external interfaces | See [Attack surface](#attack-surface) |
| (2)(k) | Reduce the impact of an incident with exploitation mitigation | The code of the workspace is Rust with `unsafe_code = "forbid"` (`Cargo.toml`, `[workspace.lints.rust]`, inherited by every crate), `unwrap_used` is a lint warning, and CI treats warnings as errors. The API client limits body size and time. The impact of a leaked token is bounded by revocation at the app (T12) |
| (2)(l) | Record and monitor relevant internal activity, with an opt-out | See [Security logging](#security-logging) |
| (2)(m) | Users can securely and easily remove all data and settings permanently; secure transfer where data can be moved | Removal is in [Decommissioning](user-information.md#decommissioning): `logout` for each profile, deleting the configuration directory and uninstalling by the channel used. The CLI has no export or import of settings, so there is no transfer of data to other products to secure |

## Requirements of Annex I, Part II

| Point | Requirement | Where it is met |
|---|---|---|
| (1) | Identify and document vulnerabilities and components; SBOM in a common machine-readable format | Each release publishes a CycloneDX SBOM per archive, signed, and the container image carries one as an attestation ([user-information.md](user-information.md#software-bill-of-materials); the `sbom` job of `.github/workflows/release.yml`). Dependencies are tracked in `Cargo.lock`, monitored as in T10, and reviewed monthly ([CONTRIBUTING.md](../CONTRIBUTING.md#dependency-updates)) |
| (2) | Fix vulnerabilities without delay; security updates separate from functionality updates where feasible | Fix targets by severity are in [SECURITY.md](../SECURITY.md#severity-and-fix-targets). In the 0.x series, fixes go into the latest 0.x release, which can also carry other changes; the release notes mark the security entries under "Security". Separate security-only releases are not promised |
| (3) | Effective and regular tests and reviews of security | The tests, scans and their schedule are in [CONTRIBUTING.md](../CONTRIBUTING.md#security-testing) (`ci.yml`, `security-tests.yml`, `workflow-lint.yml`, `scorecard.yml`). This document is reviewed as described in [Review](#review) |
| (4) | Disclose information about fixed vulnerabilities once an update is available | Every fixed vulnerability gets a GitHub security advisory written from [security-advisory-template.md](security-advisory-template.md): description, affected and fixed versions, severity, workarounds ([SECURITY.md](../SECURITY.md#how-advisories-are-published)) |
| (5) | A coordinated vulnerability disclosure policy | [SECURITY.md](../SECURITY.md#coordinated-disclosure): confidentiality until the advisory, 90 days, safe harbour |
| (6) | Facilitate sharing information about vulnerabilities, with a contact address | Private reporting on GitHub, `security@hodeitek.com` and `security.txt` ([SECURITY.md](../SECURITY.md#reporting-a-vulnerability)). Vulnerabilities found in third-party components are reported to their maintainers, with any fix, and recorded as described in [third-party-components.md](third-party-components.md#reporting-a-vulnerability-to-the-components-maintainers) |
| (7) | Mechanisms to securely distribute updates; automatic where applicable | Releases are signed and verifiable ([verifying-releases.md](verifying-releases.md), [release-signing.md](release-signing.md)); each channel (release archive, Homebrew, Scoop, packages, MSI, `install.sh`, container image, `cargo install`) has its update command ([user-information.md](user-information.md#updating)). Automatic installation does not apply (see [No automatic updates](#no-automatic-updates)). The APT and DNF repository key is tracked in [#114](https://github.com/Hodeitek/hodeishield-cli/issues/114) |
| (8) | Disseminate security updates without delay, free of charge, with advisory messages | Updates are public downloads that need no subscription ([SECURITY.md](../SECURITY.md#supported-versions)). They are announced in the advisory, the notice at the top of the README and the release notes, in that order ([SECURITY.md](../SECURITY.md#security-notices)) |

## Decisions

### No automatic updates

**Decision.** The CLI never updates itself. It tells the user, on an interactive terminal and at most
once a day, that a newer release exists, and the user updates through the channel used to install it.

**Reasons.**

- The CLI is installed through eight channels, each with its own update command and its own
  verification ([user-information.md](user-information.md#updating)). Package managers, the MSI and
  container tags already provide controlled updates; a built-in updater would be a second, parallel
  path to maintain and to secure.
- An updater needs to replace the binary, which is often owned by root or by a package manager, and
  to fetch and verify code on its own. That would add a write path and a download path to a tool
  whose design is read-only, and the user would no longer decide when new code runs with their
  credentials.
- Users who need to pin a version, such as pipelines using a container digest, would have to opt out
  of the updater to stay reproducible.
- Where a fix is urgent, the notice and the advisory reach users without installing anything for
  them ([SECURITY.md](../SECURITY.md#security-notices)).

**What the update check sends.** One unauthenticated `GET` to
`https://api.github.com/repos/Hodeitek/hodeishield-cli/releases/latest`, with a 2 second limit and only
the `User-Agent` (`hodeishield-cli/<version>`) and `Accept` headers; no credential, profile, tenant,
command or machine identifier. GitHub sees the user's IP address. It runs at most once in 24 hours,
only when standard error is a terminal, and never with `--json`, `--csv`, `completions` or when `CI`
is set (`update_check.rs`, module comment; [README.md](../README.md#new-version-notice)). The endpoint
can be replaced only by a loopback address, which is for tests (`endpoint_for`).

**How to turn it off.** Set `HODEISHIELD_NO_UPDATE_CHECK` to any non-empty value, or run
`hodeishield config set update_check false`; with either, no request is made
([user-information.md](user-information.md#updating)).

### Security logging

**Decision.** The CLI does not keep a log of its activity. It writes request diagnostics to standard
error only when the user passes `--verbose`.

**Reasons.**

- Annex I, Part I, point (2)(l) asks products to record relevant internal activity "where
  applicable". The CLI is a short-lived local process without accounts, privileged functions or
  stored user data other than tokens in the keychain. The accesses to the organisation's data that
  matter for security happen at the service, which authenticates every request; that is where they
  can be recorded and monitored.
- A log file would be a new asset: it would hold URLs with filter values and identifiers from the
  user's organisation and would need protection, rotation and removal in
  [Decommissioning](user-information.md#decommissioning). Without a log, nothing is recorded that the
  user would need to opt out of.
- The user can see what is happening when they ask. With `--verbose` the CLI writes, for each API
  request, the method (always `GET`), URL, status, time and request id, and each retry with its
  reason (`commands/mod.rs`, observers; `client.rs`, `RequestEvent` and `RetryEvent`), plus the
  reason an update check showed nothing. It never writes a header, token, key or response body. The
  URL can include identifiers and filter values, which the user should treat as their organisation's
  data ([user-information.md](user-information.md#security-properties-and-secure-use)).
- Failures that point to unauthorised access or corruption are not hidden: they end with a distinct
  exit code and a message, and carry the service's request id when there is one ([README.md](../README.md#exit-codes)).

### Attack surface

**Decision.** The CLI exposes no network listener except during sign-in, makes outgoing requests only
to the configured HodeiShield hosts and to GitHub for the update check, and sends nothing but `GET`
requests to the API.

| Interface | State | Control |
|---|---|---|
| Outgoing network to the API | HTTPS only, no redirects, `GET` only, 30 s timeout, 8 MiB body limit | `hodeishield-api/src/client.rs`, `build`, `MAX_RESPONSE_BYTES` |
| Outgoing network to the app (sign-in, refresh, revoke) | HTTPS only, no redirects, `POST` to the OAuth token, device and revocation endpoints | `auth/oauth.rs`, `http_client` |
| Outgoing network to GitHub | The update check, off in scripts and CI and by choice | `update_check.rs` |
| Local listener | `127.0.0.1`, random port, during `login` only, one callback, bounded in time; not started with `--device` | `auth/loopback.rs` |
| Starting a program | The user's browser, to open the sign-in page; `--no-browser` skips it | `commands/session.rs`, `webbrowser::open` |
| Keychain | The platform store through `keyring-core`; entry `hodeishield-cli`, one account per profile | `auth/store.rs` |
| Configuration file | `config.toml`, read at start, written by `config set`; path from `HODEISHIELD_CONFIG` or the platform's directory | `config.rs` |
| Environment variables | `HODEISHIELD_API_KEY`, `_PROFILE`, `_API_URL`, `_APP_URL`, `_CONFIG`, `_OAUTH_CLIENT_ID`, `_NO_UPDATE_CHECK`, and the standard proxy and certificate variables. Two more exist for the tests: the update-check URL, honoured only for a loopback address, and a stand-in for a terminal | `config.rs`, `auth/mod.rs`, `update_check.rs`, README "Configure" |
| Command line | Parsed with `clap`; the CLI reads no file other than its configuration and update-check record, and runs no command taken from the server | `cli.rs`, `config.rs`, `update_check.rs` |
| Proxy and certificates | The system's, with no option to disable verification | README "Networking" |

The workspace crates forbid `unsafe` code. The build tool `xtask` is not shipped.

### Data minimisation

**Decision.** The CLI keeps and sends only what it needs to do its reads and to keep a person signed
in, and it collects no telemetry.

- **Stored on the machine.** The keychain entry for each signed-in profile: access token, optional
  refresh token, expiry, scope, issuer, API URL and client id (`auth/store.rs`, `Payload`).
  `config.toml`: URLs, OAuth client id and scopes, default profile and the update-check setting
  (`config.rs`, `ConfigFile`, `Profile`). `update-check.json`: the time of the last check and the
  version found (`update_check.rs`, `Cache`). Nothing else is written; command output goes to
  standard output only.
- **Sent to the API.** The credential as a bearer token in the `Authorization` header, marked sensitive so it stays out of debug output, `Accept: application/json` and the
  user agent `hodeishield-cli/<version>`, and the query of the command (`client.rs`, `build`).
- **Sent to the app.** The authorization request, with a PKCE challenge and `state`, and the token,
  device and revocation requests (`auth/oauth.rs`).
- **Sent to GitHub.** The update check described above, unless turned off.
- **Not collected.** There is no analytics, crash reporting or usage counting in the code of the
  workspace: a case-insensitive search of `crates/`, `xtask/` and the manifests for telemetry,
  analytics, tracking, metrics and the names of common reporting services finds nothing. The only
  outgoing requests are the ones listed above. A search is not a proof for the dependencies; the
  components of each release are listed in its SBOM.

## Residual risks

- Code running as the same user can read the environment, the keychain once it is unlocked, and the
  user's files. The CLI does not defend against it; revoking access at the app limits the damage.
- A tenant API key in the environment is visible to the processes of the same user and to anything
  that records the environment. Keeping it in a secret store and giving it only read scopes reduces
  this ([user-information.md](user-information.md#security-properties-and-secure-use)).
- The CLI trusts the operating system's certificate store, so a certificate authority installed in it
  can read traffic. This is how inspecting proxies are supported; use behind one is verified on Linux
  only ([README.md](../README.md#networking-proxies-and-tls-inspection)).
- The macOS binary is not signed with an Apple Developer ID or notarized; the Sigstore signature is
  the proof that it is genuine ([#50](https://github.com/Hodeitek/hodeishield-cli/issues/50)).
- `install.sh --no-verify` skips the signature check; the checksum alone does not prove who built a
  file.
- A Sigstore signature cannot be revoked; users are protected by verifying the exact tag and by the
  advisory ([release-signing.md](release-signing.md#if-the-release-workflow-identity-is-compromised)).
- The update check tells GitHub the user's IP address, unless turned off.
- Without a keychain, a person cannot sign in and must use a tenant API key (see
  [Token store](#token-store)).
- `logout` cannot yet remove a keychain entry it cannot read; signing in again replaces it
  ([#154](https://github.com/Hodeitek/hodeishield-cli/issues/154)).

## Review

This document is reviewed:

- when the threat model changes: a new command that writes or that reads a new kind of data, a new
  authentication method, a new distribution channel or signing identity, a new credential store, a
  new network destination, or a decision in [docs/decisions](decisions) that changes any of them;
- when a vulnerability is fixed, to check whether the assessment missed it;
- at least at each minor release.

Each review records its date, the version and what changed, even when the answer is "no change".

| Date | Version | Note |
|---|---|---|
| 2026-10-12 | 0.4.1 | First version |
