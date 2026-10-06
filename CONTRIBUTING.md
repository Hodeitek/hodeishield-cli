# Contributing

Thanks for helping. Bug reports, fixes and documentation improvements are welcome.

## Ground rules

- **The CLI only reads.** Changes that write to the API will not be accepted; the `/v1` API is
  read-only anyway.
- **Credentials never leave the keychain or the environment.** No change may write a token or key to
  a file, print it, or log it. Tests assert this; keep them passing.
- **Do not include real data** in issues, tests or examples: no real API keys, tokens, tenant names,
  hostnames other than the public `*.hodeishield.com`, or customer data. Use `example.com` /
  `example.test` and made-up values.
- **Write in English.** Issues, pull requests, commit messages, milestones and labels are in
  English. Quote any product text as it appears, in its own language.

## Issues

Each issue covers one actionable thing. Its title is lowercase and names the measured defect or
gap, not the fix (e.g. `whoami does not show which tenant the credential reads`). Its body has
these sections:

- **Measured**: the evidence, such as a `file:line`, URL, command or output. Mark anything assumed.
- **Why it matters**: who it affects.
- **Acceptance criteria**: checks someone else can verify.
- **Depends on**: other issues, including in other repositories, or `Nothing.`

## Development

You need the Rust toolchain pinned in `rust-toolchain.toml` (installed automatically by `rustup`).

```sh
cargo build                       # builds the CLI (target/debug/hodeishield)
cargo test --workspace            # unit and end-to-end tests (no network, no keychain needed)
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo xtask codegen --check       # the API client matches openapi/v1.json
cargo deny check && cargo audit   # dependency policy and advisories
```

CI runs the tests on Linux, macOS and Windows and the other checks on Linux; a pull request needs
them all green.

### Dependency updates

Dependabot (`.github/dependabot.yml`) proposes cargo and GitHub Actions updates once a week, against
`dev`, for versions published at least seven days earlier. Major versions are left to a person.

Three pins are not covered by Dependabot and are reviewed by hand in the periodic dependency review:

- the Rust toolchain in `rust-toolchain.toml` (latest stable, at least seven days old);
- `cargo-deny` and `cargo-audit`, installed with `--version` in `.github/workflows/ci.yml`.

The same review runs `cargo audit` and `cargo outdated`, and checks that every action is pinned by
full commit SHA. The MSRV (`rust-version` in `Cargo.toml`) is a compatibility promise, not a
dependency: it changes only by a deliberate decision.

### The API client is generated

`crates/hodeishield-api/src/generated.rs` is generated from the vendored OpenAPI document
`openapi/v1.json` by `cargo xtask codegen`. Do not edit it by hand. To follow a new version of `/v1`,
see [openapi/README.md](openapi/README.md).

### Trying the CLI against your organisation

Create a tenant API key with read scopes in the app (*Settings → API keys*), then:

```sh
export HODEISHIELD_API_KEY=...   # never commit or paste it anywhere
cargo run -- vendors list
```

## Pull requests

- Branch from `dev` and open the pull request against `dev`. `main` only receives releases.
- Keep changes focused, with tests for new behaviour.
- Commits must be signed (GPG or SSH) and use a clear, imperative message in English. Reference
  the issue it resolves with `Closes #N` in the commit message.
- Commit messages and pull request descriptions must not mention Claude: no session trailer, no
  co-author line, no claude.ai link, and not the word itself. Enable the local check with
  `git config core.hooksPath .githooks`; CI runs the same check on every pull request.
- Every commit must be signed off: it needs a `Signed-off-by: Name <email>` trailer matching the
  commit author, which certifies the [Developer Certificate of Origin 1.1](https://developercertificate.org/).
  Add it with `git commit -s`. Merge commits count too (`git merge --signoff`). If you forgot, use
  `git commit --amend -s` for the last commit or `git rebase --signoff <base>` for several. CI
  checks every pull request; sign-off is never added automatically.
- By contributing you agree that your contribution is licensed under the Apache License 2.0.

## Security issues

Do not open a public issue: see [SECURITY.md](SECURITY.md).
