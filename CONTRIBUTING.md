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
- Commits must be signed (GPG or SSH) and use a clear, imperative message.
- By contributing you agree that your contribution is licensed under the Apache License 2.0.

## Security issues

Do not open a public issue: see [SECURITY.md](SECURITY.md).
