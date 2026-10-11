# 0001. Signing in on a machine without a keychain

- Status: Accepted
- Issue: [#39](https://github.com/Hodeitek/hodeishield-cli/issues/39)
- Related: [#101](https://github.com/Hodeitek/hodeishield-cli/issues/101) (fail-closed sign-in),
  [#111](https://github.com/Hodeitek/hodeishield-cli/issues/111) (keychain out of reach in a remote
  session)
- Deciders: maintainers

## Context

`hodeishield login` keeps its tokens (an access token and, by default, a refresh token) in the system
keychain: macOS Keychain, Windows Credential Manager, or on Linux the Secret Service over D-Bus
(`crates/hodeishield-cli/src/auth/store.rs`). Until this decision there was no other place to keep
them, and the README promised that tokens are "never in a file".

On a machine with no keychain (an SSH or jump host, a container, WSL without a desktop session, a CI
runner) this is what happens:

- `login` checks that the keychain can keep a session **before** it opens a browser or shows a device
  code, and stops with a pointer to `HODEISHIELD_API_KEY` (`commands/session.rs`).
- If saving fails after the app has issued tokens, the CLI revokes the refresh token and then the
  access token, says so, and exits non-zero, so no grant is left that nothing holds.
- Other commands, with no API key set, exit 3 and say that the keychain is not available in this
  session.
- `--device` removes the need for a browser, so storage is the only blocker.

Who is affected: people who work from a jump host with their own identity (the case in the issue),
containers, and CI. A tenant API key works everywhere, but it is one more long-lived secret per
tenant, it is not tied to a person, and someone has to create and track it.

The asset is the refresh token. It is long-lived, covers one tenant with the read scopes chosen at
consent, belongs to one person, and ends with `logout` or when it is revoked in the app. The access
token is short-lived.

| Who can read it | Keychain | File readable only by its owner | API key in the environment |
|---|---|---|---|
| Code running as the same user | Yes, if the keychain is unlocked | Yes | Yes (and child processes inherit it) |
| Other users | No | No, if owner and mode are right | Depends on where it is kept |
| `root` | Yes | Yes | Yes |
| Backups, snapshots, disk images | Encrypted at rest | Plaintext | Plaintext if kept in a file |
| A container layer, if sign-in ran at build time or a signed-in container is published | Not applicable | Plaintext | Same through `ENV` or `ARG` |
| A network home directory (NFS) | Encrypted | Readable by the server's administrators and by `root` elsewhere | Same |

On a machine with no keychain, a file readable only by its owner is weaker than a keychain mainly
against offline copies; against code already running as the user it is about the same. Compared with
the alternative that exists today, the refresh token has the same kind of exposure as an API key, but
it belongs to one person, can be attributed to that person, and `logout` revokes it. An API key lives
until someone revokes it by hand.

## Options considered

- **A. Keychain only; document API keys.** Strongest, and nothing new to protect. A person still
  cannot use their own identity on a jump host. Already in place, and kept as the default.
- **B. Plain-text file, opt-in.** Small to medium effort; works wherever there is a file system. The
  weakest storage, so it must be an explicit choice with checks on the file.
- **C. Encrypted file with a passphrase.** Protects copies of the file, but a prompt on every command
  does not fit scripts, a passphrase in the environment is no better than B against code running as
  the same user, and a weak one makes the file a target for offline guessing. Large: key derivation
  and encryption dependencies to vet, a versioned format, sessions with no terminal.
- **D. Linux kernel keyring.** Secrets never reach disk, backups or container layers. But nothing
  survives a reboot, a session keyring ends with its session (a new SSH login usually gets a new
  one), the persistent keyring expires, and container runtimes often block the system call.
- **E. No stored refresh token** (print an access token once, to be exported). Short exposure, but no
  refresh and not usable by unattended jobs, which should use an API key anyway.
- **F. An external credential helper.** Shifts the trust to a configured program; justified only with
  a larger audience.

## Decision

Keep the keychain as the default and add **an opt-in token store that is a plain-text file** (B), with
the following rules. Containers and CI keep using API keys.

- **Opt-in only.** `HODEISHIELD_TOKEN_STORE=plaintext-file`, or the global configuration key
  `token_store = "plaintext-file"`. There is no per-profile option and no flag on `login`, because
  every command must read from the same store. The environment wins over the configuration file. The
  only other accepted value is `keychain`; anything else is an error (exit code 1) before any network
  call.
- **No fallback in either direction.** With the default, nothing changes and no file is ever written,
  also when the keychain is missing. With the opt-in, the keychain is never touched. Tokens are never
  moved between stores: sign out, change the setting, sign in again.
- **Location.** The platform's state directory, not the configuration directory:
  `$XDG_STATE_HOME/hodeishield/sessions/` (by default `~/.local/state/hodeishield/sessions/`) on
  Linux, and on macOS a sibling of the application support folder
  (`~/Library/Application Support/com.Hodeitek.HodeiShield.sessions/`), because there the
  configuration and data directories are the same folder. One file per profile, named by the SHA-256
  of the profile name (names may contain `/` or `..`; the hash is not a way to hide a guessable
  name). The configuration file stays free of credentials, so copying or syncing it never copies a
  token. The parents of the sessions directory are not walked or checked, because that would refuse
  legitimate setups; the README says they must not be writable by other users.
- **Checks on every read and write.** The CLI refuses, and never repairs, a file or directory that is
  a symbolic link, is not owned by the current user, or has any group or other permission bit. It
  creates the directory with mode 700 and the files with mode 600. The directory is opened once
  without following links and checked on the open handle; every later operation is relative to that
  handle, so replacing the path afterwards cannot redirect it. Files are opened without following
  links and without blocking, and checked again after they are opened. Running as `root` for a
  user's home is not special-cased: a directory of another owner is refused in both directions. A corrupt file is an error that names
  it; a file written for another profile is not accepted.
- **Atomic writes.** The CLI writes a new file created with mode 600 in the same directory, flushes it
  to disk, renames it over the target and flushes the directory. A temporary file is removed when
  anything fails, and no token is ever in a file that others can read. Leftovers of a crash (a
  temporary file of that profile older than a minute) are removed on the next save or logout.
- **Behaviour of #101 is unchanged.** `login` checks that the selected store is usable before it
  opens a browser or shows a code. If saving fails after the exchange, the refresh token and then the
  access token are revoked and the command exits non-zero. `logout` revokes, then deletes the file.
  No new exit codes: `login` and `logout` failures are 1, other commands that need a credential and
  find the file refused are 3, a corrupt file is 1.
- **Windows is deferred.** There are no permission bits to check, and setting and checking an ACL
  needs platform calls that the workspace's `unsafe_code = "forbid"` rules out without a vetted
  wrapper. Selecting the file store on Windows is refused with exit code 1, before anything is asked
  of the app.
- **Network home directories.** Documented, not refused. On Linux the CLI also warns on `login` when
  the directory is on NFS or SMB, where that can be told cheaply from the file system type; elsewhere
  it cannot be told reliably, so only the documentation covers it.
- **Messages.** When the keychain is not available, the hint keeps the API key first and offers the
  opt-in second, with one line on the trade-off: tokens are stored unencrypted in a file only you can
  read. The README has a section for servers, containers and remote sessions with the same order and
  no container recipe for the file store.
- **No telemetry.** The choice of store never leaves the machine.

## Consequences

- The README promise "tokens never in a file" becomes "in the system keychain unless you opt in".
  Every place that said so (README, `login --help`, contributing and security notes) is updated.
- People on a jump host can sign in as themselves. They accept the exposure in the table above for
  that machine; the README says so next to the instructions.
- A new class of local failure exists (a loosened mode after a copy or restore, a symbolic link, a
  file owned by another user). The CLI refuses and explains instead of repairing, so a mistake is
  visible rather than silently fixed or silently tolerated.
- Deleting the file, or restoring it from a backup, does not end or restore a session; only the
  revocation at the app does. `logout` therefore revokes first.
- A configuration file with `token_store` is refused by older CLIs (unknown field). The environment
  variable avoids that.
- The tests run in the normal suite, including the refusals (symbolic link, wrong owner, wrong modes,
  invalid setting, no fallback, Windows).

## Deferred

- **Windows.** Needs an ACL design and either a vetted wrapper crate or an exception to
  `unsafe_code = "forbid"`.
- **Linux kernel keyring.** Not worth a spike until users on SSH servers report that the file store
  does not fit, for example because data on disk is the main concern. Its lifetime rules (above) make
  it a surprising default.
- **An encrypted file** (option C), **an access-token-only sign-in** (option E) and **a credential
  helper** (option F), for the reasons above.
- **Migration between stores.** Deliberately absent; switching is sign out, change the setting, sign
  in.

## Open question

To be confirmed with the API provider: the refresh token's lifetime, rotation and idle expiry on the
server side. They decide how long a copy of a token file stays useful, and whether the exposure of a
leaked file can be bounded by something other than revocation. Nothing in this decision depends on the
answer, but the README's wording about exposure should be revisited once it is known.
