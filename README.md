# hodeishield

HodeiShield CLI — the official command-line client for [HodeiShield](https://app.hodeishield.com), by
[Hodeitek](https://hodeitek.com).

Read your third-party inventory, supply-chain alerts, risk register, compliance posture, evidence and
endpoint agents from a terminal or a script.

- **Read-only.** Every command is a `GET` against the public `/v1` API. Nothing here can change data in
  your organisation.
- **Safe with credentials.** Sign-in tokens live in the system keychain, never in a file; nothing is
  ever printed or logged; credentials only travel over HTTPS and are never replayed to a redirect.
- **Built for scripts.** `--json` prints the API's own JSON, exit codes say what went wrong, and
  `HODEISHIELD_API_KEY` works without any interactive step.
- **Verifiable.** Every release is signed with Sigstore (keyless, from GitHub Actions) and carries
  SLSA build provenance.

> The CLI is at version 0.x: commands and output may still change before 1.0.

## Install

Download the archive for your platform from the
[latest release](https://github.com/Hodeitek/hodeishield-cli/releases/latest), **verify it** (next
section), and put `hodeishield` (`hodeishield.exe` on Windows) somewhere on your `PATH`.

| Platform | Archive |
|---|---|
| Linux x86_64 | `hodeishield-<version>-x86_64-unknown-linux-musl.tar.gz` |
| Linux arm64 | `hodeishield-<version>-aarch64-unknown-linux-musl.tar.gz` |
| macOS (Apple silicon and Intel) | `hodeishield-<version>-universal-apple-darwin.tar.gz` |
| Windows x86_64 | `hodeishield-<version>-x86_64-pc-windows-msvc.zip` |

`<version>` has no leading `v`: release `v0.1.0` ships `hodeishield-0.1.0-…`. The Linux binaries are
statically linked and run on any distribution. A Homebrew tap and a Windows installer (MSI) are
planned but not available yet.

From source, with the Rust toolchain installed (pin the release tag you want):

```sh
cargo install --locked --git https://github.com/Hodeitek/hodeishield-cli --tag v0.1.0 hodeishield-cli
```

## Verify a download

Each release has a `SHA256SUMS` file, a Sigstore bundle (`*.sigstore.json`) for every archive and for
`SHA256SUMS`, and SLSA provenance (`hodeishield.intoto.jsonl`). In short:

```sh
sha256sum --ignore-missing -c SHA256SUMS

cosign verify-blob hodeishield-0.1.0-x86_64-unknown-linux-musl.tar.gz \
  --bundle hodeishield-0.1.0-x86_64-unknown-linux-musl.tar.gz.sigstore.json \
  --certificate-identity https://github.com/Hodeitek/hodeishield-cli/.github/workflows/release.yml@refs/tags/v0.1.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-github-workflow-trigger push
```

A valid signature proves the file was built by this repository's release workflow from exactly that
tag, with no long-lived key involved; put your version in the identity rather than matching any tag. The full steps, including the provenance check with `slsa-verifier`, are in
[docs/verifying-releases.md](docs/verifying-releases.md).

## Authenticate

### With a tenant API key (scripts, CI, servers)

Create a key in [the app](https://app.hodeishield.com) under **Settings → API keys**, with only the
read scopes you need, and export it:

```sh
export HODEISHIELD_API_KEY=hsk_...
hodeishield whoami
```

When `HODEISHIELD_API_KEY` is set it is used for every call, whatever else is configured. Keep it in
your CI's secret store; the CLI never prints it.

### By signing in (people)

```sh
hodeishield login            # opens the browser; the app redirects back to 127.0.0.1
hodeishield login --device   # no browser here: approve a short code from another device
hodeishield whoami
hodeishield logout           # revokes the token at the app and removes it from the keychain
```

You sign in to [app.hodeishield.com](https://app.hodeishield.com) as usual (2FA, passkey or SSO), and
on the consent screen you choose **the one tenant** the CLI may read. A sign-in token never covers
more than that tenant, and it only reads. To use another tenant, sign in again with another profile (`--profile`).

With `--device`, open the address the CLI prints on any device and **type the code by hand**: the app
does not accept a link with the code filled in, on purpose.

The CLI asks for the read scopes its commands need (vendors, alerts and risks; every compliance
framework the app offers; evidence; endpoints) and for a refresh token. To ask for fewer, set them:
`hodeishield config set oauth_scopes "supply_risk:read offline_access"`.

The token is kept in the system keychain (macOS Keychain, Windows Credential Manager, or the Secret
Service — GNOME Keyring, KWallet — on Linux) and refreshed automatically, also when the app ends an
access token early (signing out of the web session you approved a browser sign-in from does). Without
a keychain, signing in is refused rather than falling back to a file: use an API key there.

To cut the CLI's access from elsewhere, revoke it in [the app](https://app.hodeishield.com) under
**Account → Application access**.

## Use

```sh
hodeishield vendors list --criticality critical
hodeishield vendors get 0b8f2a52-6a0e-4d5c-9d3e-1f2a3b4c5d6e
hodeishield alerts list --status open --since 2026-01-01T00:00:00Z
hodeishield risks list --min-inherent-score 15 --sort inherent_score
hodeishield compliance posture nis2
hodeishield compliance controls --framework nis2 --status failing
hodeishield evidence list --expiring-before 2026-12-31T00:00:00Z
hodeishield endpoints list --status active
```

```console
$ hodeishield vendors list --criticality critical
ID                                    NAME             DOMAIN               CRITICALITY  ACTIVE  LAST SCAN
0b8f2a52-6a0e-4d5c-9d3e-1f2a3b4c5d6e  Example Hosting  hosting.example.com  critical     yes     2026-09-27 06:12Z
5c1d9e0a-3b7f-4a2e-8c6d-2e4f6a8b0c1d  Sample Payments  pay.example.net      critical     yes     2026-09-26 22:40Z
```

Lists show one page (50 items by default); `--page`, `--per-page` (up to 200) and `--all` walk the
rest. Every list takes `--sort` and `--order`; `--help` on any command lists what it accepts.

### JSON for scripts

`--json` prints the body the API returned, unchanged, including fields newer than your CLI. With
`--all`, it prints a single JSON array of every item:

```sh
hodeishield alerts list --status open --all --json | jq -r '.[] | [.severity, .title] | @tsv'
```

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Error (invalid input, configuration, unexpected answer) |
| 2 | Invalid command line |
| 3 | Not authenticated: no credential, or the API rejected it |
| 4 | The credential lacks the scope the command needs |
| 5 | Not found (or not in your organisation) |
| 6 | Rate limit exhausted (the CLI already retried short waits) |
| 7 | The API could not be reached or failed |

Errors go to stderr with a hint and, when the API gave one, a **request id**: quote it when you
contact support. `--verbose` logs each request's method, URL, status and request id to stderr, never
a credential.

## Configure

Settings come from, in order: flags, environment variables, the profile in the configuration file,
and the defaults (`https://api.hodeishield.com`, `https://app.hodeishield.com`).

```sh
hodeishield config show                      # the settings in effect
hodeishield config path                      # where the file is
hodeishield --profile staging config set api_url https://api.example.test
hodeishield config use staging               # make it the default profile
hodeishield --profile default vendors list   # or pick one per command
```

| Variable | Purpose |
|---|---|
| `HODEISHIELD_API_KEY` | Tenant API key; takes precedence over a sign-in |
| `HODEISHIELD_PROFILE` | Profile to use |
| `HODEISHIELD_API_URL` | API base URL |
| `HODEISHIELD_APP_URL` | App base URL (sign-in) |
| `HODEISHIELD_CONFIG` | Path of the configuration file |

The configuration file holds URLs and sign-in settings only, never a credential. URLs must use HTTPS;
plain HTTP is accepted only for `localhost`.

Shell completions: `hodeishield completions bash|zsh|fish|powershell|elvish`.

## Repository layout

- `crates/hodeishield-cli` — the `hodeishield` binary.
- `crates/hodeishield-api` — a Rust client for `/v1`, generated from the API's published OpenAPI
  document vendored in [`openapi/v1.json`](openapi/README.md). It ignores fields it does not know, so
  it keeps working as `/v1` grows.
- `xtask` — the generator (`cargo xtask codegen`, and `--check` in CI).

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md). To report a vulnerability, use
[private reporting](https://github.com/Hodeitek/hodeishield-cli/security/advisories/new), never a
public issue ([SECURITY.md](SECURITY.md)).

## License

[Apache License 2.0](LICENSE).

## About

- [HodeiShield](https://app.hodeishield.com): the third-party risk, supply-chain security and
  compliance platform that this CLI reads from; sign in there and create API keys.
- [Hodeitek](https://hodeitek.com): the company that builds HodeiShield and maintains this CLI.
