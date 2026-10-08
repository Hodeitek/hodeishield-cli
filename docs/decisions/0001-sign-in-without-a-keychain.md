# 0001. Signing in on a machine without a keychain

- Status: Proposed
- Issue: [#39](https://github.com/Hodeitek/hodeishield-cli/issues/39)
- Deciders: maintainers

This is a proposal. Nothing here is decided or implemented; the recommendation is the author's.

## Context

`hodeishield login` stores its tokens (an access token and, by default, a refresh token) in the
system keychain and nowhere else (`crates/hodeishield-cli/src/auth/store.rs:1-6`). On Linux the only
backend is the Secret Service over D-Bus, through `zbus-secret-service-keyring-store`
(`crates/hodeishield-cli/Cargo.toml:47-48`, `store.rs:127-131`). There is no kernel keyring (keyutils)
backend and no file fallback.

On a machine with no Secret Service (an SSH server, a container, WSL without a desktop session, a CI
runner) this is what happens today:

- The store is first touched when the token is saved (`commands/session.rs:100`), after the whole
  browser or `--device` flow has finished. The person completes sign-in and consent, then gets
  "the system keychain is not available" (`store.rs:17,100-110`). The token already issued is not
  revoked by the CLI, so it stays valid at the app until revoked there.
- The error points to `HODEISHIELD_API_KEY` (`auth/mod.rs:87-97`); the README says the same
  (`README.md:294-297`, and for containers `README.md:160-161`).
- `--device` does not help: it avoids the browser, not the storage.

Who is affected: people who work from a jump host or a remote shell with their own identity (the
motivating case in the issue: MSSP staff), containers, and CI. A tenant API key works everywhere
(`auth/mod.rs:38-45`), but it is one more long-lived secret per tenant, it is not tied to a person,
and someone has to create it.

What is at stake: a sign-in token reads one tenant's supply-chain risk data. The access token is
short-lived; the refresh token is long-lived and is the sensitive part. The README promises that
tokens are "never in a file" (`README.md:30`, `cli.rs:103-104`), so any option that writes a file
changes a documented guarantee.

Existing seam: `TokenStore` (`store.rs:87-93`) has `load`, `save` and `delete` per profile, with a
test-only `MemoryStore` (`store.rs:185`). The CLI builds the store in one place
(`commands/mod.rs:83`). A new store is a new implementation of that trait plus a way to choose it.

## Options

### A. Keep keychain-only; document API keys for headless use

Change nothing in behaviour. Improve the experience: refuse early (before opening a browser or
printing a device code) when no keychain is reachable, and say what to do; expand the README with a
"servers and containers" recipe.

- Security: best. No new storage, no weaker path. API keys can be scoped to read scopes and rotated.
- Effort: small (an early check, a message, docs).
- Consequences: the issue's use case is answered with "request an API key", not with the person's own
  identity. Per-tenant keys must be issued and tracked by someone.

### B. Linux kernel session keyring (keyutils) as a fallback

Store the payload with `keyctl` in the session or user keyring when no Secret Service is present.

- Security: the secret is kernel memory, never on disk, and not readable by other users. But it is
  scoped to a keyring, not a person's login: a user keyring is readable by every process of that user;
  a session keyring is visible only to that session's processes.
- Lifetime: it does not survive a reboot. A session keyring disappears when the last process of the
  session ends, so a new SSH connection would be signed out; a user keyring (`@u`) survives
  across sessions until reboot or key timeout, but with defaults that vary by distribution and
  container runtime. Containers often block the `keyctl` syscall under the default seccomp profile.
- Effort: medium. A new backend crate (or direct syscalls), Linux only, behind a selection rule and
  tests that need a real kernel keyring.
- Consequences: helps SSH servers somewhat, containers and WSL unreliably. Behaviour (survives or not)
  would be surprising to users and needs documenting per mode.

### C. Encrypted file store with a passphrase

Write the payload to a file in the config directory, encrypted with a key derived (for example with
Argon2id) from a passphrase.

- Where the key comes from: a prompt on a terminal, or an environment variable / file descriptor for
  non-interactive use (for example `HODEISHIELD_PASSPHRASE`).
- UX: a prompt on every command that needs the token, or a passphrase in the environment, which in
  practice moves the secret from one place to another. Without a terminal and without the variable
  the command must fail clearly.
- Threat model: protects a stolen disk, backup or file copy; does not protect against code running as
  the same user once the passphrase is in memory or in the environment. A weak passphrase makes the
  file an offline-guessing target for a long-lived refresh token.
- Effort: large. New crypto dependencies to vet (`deny.toml`), file format and versioning, prompting,
  locking against concurrent refreshes, key rotation, tests.
- Consequences: works in all environments with a terminal; the largest new security surface to own.

### D. Plaintext file with 0600 permissions behind an explicit opt-in

Store the payload in a file in the config directory, mode 0600 in a 0700 directory, only when the
person opts in (for example `HODEISHIELD_INSECURE_STORAGE=file` or a config key), with a warning on
every sign-in.

- Security: weakest. Anyone who can read the file (same user, root, backups, a mis-mounted volume, an
  image layer) holds a refresh token valid until revoked. Permissions do not protect against malware
  running as the user. This reverses the "never in a file" promise for those who opt in.
- Effort: small to medium (store, permission checks and refusal if the file is looser than 0600,
  Windows ACL handling, docs, tests).
- Consequences: common practice in other CLIs, and it solves every environment, but it normalises the
  exact exposure the CLI was designed to avoid. Requests to remove the opt-in guard would follow.

### E. No storage: print a token once or keep it in memory for one command

For example `hodeishield login --print-token` runs the flow and prints only the access token, to be
exported as an environment variable for the session; or the CLI uses the access token only within
one invocation.

- Security: good if the refresh token is never requested or never stored. The access token is
  short-lived, so exposure is limited to its lifetime; it can appear in shell history or process
  environment if handled carelessly.
- Effort: small to medium. The CLI would need to request no `offline_access` scope, accept an access
  token from the environment (a new credential source in `auth/mod.rs:38`), and print it safely
  (stdout only, never with other text).
- Consequences: no refresh, so the person signs in again when the token expires (the lifetime is set
  by the app). Fine for a short task on a jump host; poor for unattended jobs, which should use an API
  key. Interactive device flow from a remote shell is natural here.

### F. Delegate to an external credential helper

The CLI calls a configured program (as some tools do with git or Docker credential helpers) to load
and save the payload, so people bring their own vault.

- Security: depends on the helper; the CLI never writes a file. The helper's protocol and trust (the
  program path comes from configuration) become part of the threat model.
- Effort: medium (protocol, spawn without a shell, error handling, docs). Larger audience needed to
  justify it.

## Recommendation (the author's, not a decision)

Security first: the refresh token is the asset, and the options that never write it to disk or
plaintext are A, E, and B. In that order of preference:

1. Do A now, regardless: fail early, before the browser or device code, and document the headless
   path. This fixes the worst part of the current behaviour (completing sign-in and then failing,
   leaving an unrevoked token) at almost no risk.
2. Add E for the jump-host case: a sign-in that requests no refresh token and does not store anything,
   with the access token handed to the shell explicitly. It keeps personal identity without a stored
   long-lived secret, and costs one new credential source.
3. Do not implement D or C unless the maintainers accept new storage risk. If a file is needed
   anyway, prefer C over D, and only with a design review of the format and the passphrase handling.
   B is worth a spike only if SSH-server users report that E is not enough.

If the maintainers choose not to add any alternative store, the second acceptance criterion of #39 is
met by A: the README recommends API keys and explains why.

## Open questions for the maintainers

1. Is "tokens never in a file" a product guarantee to keep, or a default that an opt-in may change?
2. Can the app issue an access token without a refresh token (no `offline_access`) with a useful
   lifetime for a jump-host session? What is that lifetime?
3. Should a person's own sign-in be preferred over per-tenant API keys for MSSP staff, or are API keys
   an acceptable answer given they can be scoped and rotated?
4. For containers and CI, is an API key always the intended answer (so options B to D are out of scope
   there)?
5. Should the CLI revoke the token it just obtained when it cannot store it (today it does not)?
6. Which platforms matter most: SSH servers, WSL, containers, CI?
