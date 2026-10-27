# Contributing

Thanks for helping. Bug reports, fixes and documentation improvements are welcome.

## Ground rules

- **The CLI only reads.** Changes that write to the API will not be accepted; the `/v1` API is
  read-only anyway.
- **Credentials stay in the keychain, the environment or the opt-in token file.** No change may write
  a token or key anywhere else, print it, or log it, and nothing may fall back from one store to the
  other. Tests assert this; keep them passing.
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
cargo xtask man target/man        # generate man pages
cargo deny check && cargo audit   # dependency policy and advisories
```

CI runs the tests on Linux, macOS, Windows and Windows on Arm and the other checks on Linux; a pull
request needs them all green.

### The scripting surface is tested

`crates/hodeishield-cli/tests/contract.rs` pins what [Stability](README.md#stability) promises
scripts: the exit codes 0 to 8, the shape of `--json` output (including fields the CLI does not
know), the `--csv` header and quoting rules, and which stream carries data and which carries notes
and errors. The expectations are written out in full so a change shows in review. If one of these
tests fails, either the change is a mistake or it breaks the scripting surface: in the second case
edit the expectation on purpose and add a line under `### Changed (scripting surface)` in
`CHANGELOG.md`.

### Dependency updates

How a new dependency is chosen and reviewed, how the checks below fit together, what is done when a
dependency has a vulnerability and how it is reported to its maintainers are in
[docs/third-party-components.md](docs/third-party-components.md). A pull request that adds a
dependency answers its criteria in the description.

Dependabot (`.github/dependabot.yml`) proposes cargo and GitHub Actions updates once a week, against
`dev`, for versions published at least seven days earlier. Major versions are left to a person.

`cargo deny check` and `cargo audit` run in CI on every pull request and every push to `dev` and
`main`. Between changes, the weekly OSV-Scanner run and Dependabot alerts report new advisories
(see [Security testing](#security-testing)).

The pins Dependabot does not cover are reviewed by hand once a month, in the dependency review:

- the Rust toolchain in `rust-toolchain.toml` (latest stable, at least seven days old), together
  with the Linux build image in `packaging/build/image` (`IMAGE`, the official Rust image of the
  same version by digest; `SNAPSHOT`, the Debian snapshot that image was built from; and the exact
  `PACKAGES` versions), which `packaging/build/build.sh` refuses to use with any other version;
- `cargo-deny` and `cargo-audit`, installed with `--version` in `.github/workflows/ci.yml` and,
  with the same versions, in the `advisories` job of `.github/workflows/release.yml`; `cargo-cyclonedx`, `nfpm` (version and SHA-256) and WiX (`WIX_VERSION`; stay on 5.x until the
  licence terms of later versions have been reviewed) in `.github/workflows/release.yml`, `nfpm`
  again (version and SHA-256, the same as in `release.yml`) in
  `.github/workflows/repo-builder-tests.yml`, `oasdiff` (version and SHA-256) in
  `.github/workflows/openapi-sync.yml`, `mitmproxy` (version and SHA-256) in
  `.github/workflows/proxy-tls.yml`, and `actionlint` and `zizmor` (version and SHA-256) in
  `.github/workflows/workflow-lint.yml`;
- the image of the APT and DNF repository builder in `packaging/repo/image` (`IMAGE`, by digest, and
  the exact `PACKAGES` versions).

The same monthly review runs `cargo audit` and `cargo outdated`, and checks that every action is
pinned by full commit SHA. The MSRV (`rust-version` in `Cargo.toml`) is a compatibility promise, not
a dependency: it changes only by a deliberate decision.

### Known vulnerabilities at release

A release is not published with a known exploitable vulnerability, in the CLI or in a dependency
(Cyber Resilience Act, Annex I, Part I, point 2(a)).

- **The check.** The `advisories` job of `.github/workflows/release.yml` runs `cargo deny check
  advisories` and `cargo audit` on the tagged commit, against the current RustSec advisory database.
  The signing jobs and the publication of the draft wait for it: if it fails, nothing is signed or
  published. Its result, with the tool versions and the revision of the advisory database, is the
  last line of the release's own notes (before GitHub's list of merged pull requests), so it stays
  with the release.
- **What counts as exploitable.** Every advisory that the tools report for the tagged commit is
  treated as exploitable unless the maintainers show otherwise. Fix it by updating or replacing the
  dependency. An advisory may be accepted only when the affected code is not reachable from the CLI,
  or its conditions cannot occur in the way the CLI uses the dependency, and the reason says what was
  checked: the call path, the feature that is off, the input that never reaches it.
- **Accepting an advisory.** Add an entry to `[advisories] ignore` in `deny.toml`, through a reviewed
  pull request: `{ id = "RUSTSEC-...", reason = "<what was checked>. Review by YYYY-MM-DD." }`, with
  a review date no more than three months ahead. CI and the release refuse a bare id, a missing
  reason and a review date that has passed (`.github/scripts/advisory-exceptions.py`), and `cargo
  audit` ignores exactly that list. When the date comes, check the advisory again, then fix it or
  extend the date with a new reason. Remove the entry once the dependency is fixed.
- **Between releases.** A new advisory makes the `deny` or `audit` job of CI fail on the next change,
  and Dependabot and the weekly OSV-Scanner run report it (see [Security testing](#security-testing)).
  A vulnerability in the CLI itself follows [SECURITY.md](SECURITY.md).

### The API client is generated

`crates/hodeishield-api/src/generated.rs` is generated from the vendored OpenAPI document
`openapi/v1.json` by `cargo xtask codegen`. Do not edit it by hand. To follow a new version of `/v1`,
see [openapi/README.md](openapi/README.md). A weekly workflow reports, in an issue, when the
published document no longer matches that copy; it does not change the repository.

### Trying the CLI against your organisation

Create a tenant API key with read scopes in the app (*Settings → API keys*), then:

```sh
export HODEISHIELD_API_KEY=...   # never commit or paste it anywhere
cargo run -- vendors list
```

## Design

A short vocabulary for designing or refactoring a module, adapted from
[aihero.dev/codebase-design](https://www.aihero.dev/skills-codebase-design). A **module** is anything
with an interface and an implementation, at any scale: a function, a file, a crate. Its **interface**
is everything a caller must know to use it: signature, invariants, errors and ordering. A **seam** is
a place where behaviour can change without editing that place, and an **adapter** is a concrete
implementation plugged into one. **Depth** is the behaviour available per unit of interface, and
**locality** means that what changes together lives together.

- **Depth lives in the interface.** Judge a module by how little a caller must learn, not by how
  much code it hides. `hodeishield-api` is the model: the CLI calls `client.list_vendors(&params)`
  and gets typed results, while URL building, authentication, retries, rate limits and the response
  size cap stay behind it.
- **Deletion test.** Imagine deleting the module and inlining it into its callers. If the
  complexity vanishes, it was a pass-through and should not exist; if it spreads to every caller, it
  is earning its place.
- **The interface is the test surface.** Test through the interface. A test that reaches past it
  pins the implementation and breaks on every refactor.
- **One adapter is a hypothetical seam; two make it real.** Add a trait only when a second
  implementation exists today, a test double included. `TokenStore` qualifies: the OS keychain, the
  opt-in token file and the in-memory store used by tests all implement it.
- **Locality.** Table, JSON and CSV rendering, including the sanitising of terminal control
  characters, lives in `output.rs`, so a change to it touches one module, not every command.

## Pull requests

- Branch from `dev` and open the pull request against `dev`. `main` only receives releases.
- Keep changes focused, with tests for new behaviour.
- Add a line under `## [Unreleased]` in `CHANGELOG.md` for any change a user or a script would
  notice. A release renames that section to `## [X.Y.Z] - YYYY-MM-DD`; the release workflow refuses
  a tag without it and uses the section as the release notes. A change to the scripting surface
  goes under `### Changed (scripting surface)`; see [Stability](README.md#stability).
- Commits must be signed (GPG or SSH) and use a clear, imperative message in English. Reference
  the issue it resolves with `Closes #N` in the commit message.
- Commit messages and pull request descriptions must not mention Claude: no session trailer, no
  co-author line, no claude.ai link, and not the word itself. Enable the local check by copying the
  hook into your clone from a branch you trust, and again when it changes:
  `cp .githooks/commit-msg .githooks/check-message.sh "$(git rev-parse --git-common-dir)/hooks/"`.
  Do not point `core.hooksPath` at `.githooks`: git would then run the hooks of whatever branch is
  checked out. If you set it before, run `git config --unset core.hooksPath`. CI runs the same check
  on every pull request.
- Every commit must be signed off: it needs a `Signed-off-by: Name <email>` trailer matching the
  commit author, which certifies the [Developer Certificate of Origin 1.1](https://developercertificate.org/).
  Add it with `git commit -s`. Merge commits count too (`git merge --signoff`). If you forgot, use
  `git commit --amend -s` for the last commit or `git rebase --signoff <base>` for several. CI
  checks every pull request; sign-off is never added automatically.
- By contributing you agree that your contribution is licensed under the Apache License 2.0.

## Releases and package managers

A release starts with a signed `vX.Y.Z` tag on `main`. Release tags are protected: only members of
the organisation's release team can create, move or delete a `v*` tag, and the tag runs the
`release.yml` of the commit it points to ([docs/release-signing.md](docs/release-signing.md)).

Publishing a release (not the draft) starts the **Package managers** workflow. It verifies the
release's `SHA256SUMS` with cosign and writes the Homebrew formula, the Scoop manifest and the
winget manifests from it. After the `packaging` environment's reviewer approves, it commits the
first two to [homebrew-hodeishield](https://github.com/Hodeitek/homebrew-hodeishield) and
[scoop-hodeishield](https://github.com/Hodeitek/scoop-hodeishield) with a short-lived token of a
GitHub App installed only on those two repositories.

The same workflow's `repos` job publishes the release's `.deb` and `.rpm` packages to an APT and
a DNF repository kept in an S3-compatible bucket (`packaging/repo`). It verifies `SHA256SUMS` and the
packages, rebuilds and signs the indexes in the image pinned in `packaging/repo/image`, and uploads
the packages first and the index files last (the entry points, which are `Cache-Control: no-cache`,
after everything they list; packages and by-hash indexes are immutable, so a client holding an older
index can still finish its update). Only `hodeishield` packages vouched for by the previously signed
index (an RPM, by the repository key's signature) or by the release's verified `SHA256SUMS` are
published, and anything else found in the bucket stops the job, so write access to the bucket alone
cannot get a package signed. The `Repository builder tests` workflow checks this on every change to
`packaging/repo` and weekly (`packaging/repo/repo-test.sh`): with throwaway keys and a throwaway bucket it
publishes releases, installs and upgrades from the result with apt and dnf, and plants forged packages
and indexes that the builder and the clients must refuse. Those cases run in CI only and are not meant
to be run ad hoc. The bucket user needs list, read and write permissions
only: a release never deletes or overwrites a package, and only the subkey revocation recovery below
replaces existing packages. It runs after the same approval and is skipped while
the `packaging` environment has no `PACKAGES_S3_ENDPOINT`. It needs the variables
`PACKAGES_S3_ENDPOINT`, `PACKAGES_S3_REGION` and `PACKAGES_S3_BUCKET`, the secrets
`PACKAGES_S3_ACCESS_KEY_ID`, `PACKAGES_S3_SECRET_ACCESS_KEY` and `PACKAGES_GPG_SIGNING_KEY` (the
ASCII-armored secret signing subkey only), and the matching public key committed as
`packaging/gpg.key`.

To publish the APT and DNF repositories again, for example after the `repos` job of a release failed,
run the **Package managers** workflow by hand from `main` (`gh workflow run package-managers.yml --ref
main`). It takes no inputs: it always uses the repository's latest published release, and fails if
that release is a draft or a prerelease or if the run was not started from `main`. Only the `repos` job
runs, with the same verification of `SHA256SUMS` and the packages as on a release, using the
`packaging/repo` scripts and image on `main`, and it waits for the `packaging` environment's reviewer
like any other run. That environment must allow deployments from `main` as well as from the release tags.

The APT and DNF indexes carry no `Valid-Until`, so an older index that was once validly signed and is
served again from a compromised bucket would still verify: the weekly `repo-freshness` workflow detects
this, it does not prevent it. It checks that both repositories
are signed by that key and that the newest `hodeishield` version in each index is the latest published
release's (`packaging/repo/freshness.sh`, with `packaging/repo/freshness-test.sh` as its control in CI).
The monitor is inert only while the domain serves no APT or DNF index, that is, while `InRelease` and each
`repomd.xml` answer a clean 404 (`packaging/repo/live.sh`). Any other answer (a network or TLS error, 403,
5xx, a redirect), or a served index while `packaging/gpg.key` is missing or unreadable, fails the run, so
removing the key cannot silence it.
A failure opens an issue labelled `repo-freshness` with what was expected, what is served and the run,
and it is closed when the check passes again; a release less than 48 hours old that is not served yet
only raises a warning, since the `repos` job waits for an approval. On such an issue, first check who
can write to the bucket, then re-run the `repos` job for the latest release to publish current indexes.

Publishing a release also starts the **Container image** workflow. After the same `packaging`
environment approval, it downloads the release's two Linux musl archives and SBOMs, verifies
`SHA256SUMS` with cosign (the same identity as above) and the files against it, and builds
`ghcr.io/hodeitek/hodeishield-cli` for `linux/amd64` and `linux/arm64` from `packaging/container/Dockerfile`
without compiling anything. It pushes the exact-version tag only (no `latest`) with the job's own
`GITHUB_TOKEN` (`packages: write`, held by no other job), signs the image by digest with cosign,
attaches the SBOM with `cosign attest --type cyclonedx`, then verifies both and runs the image. Stable
releases only. The base image is pinned by digest and bumped by dependabot. The first time, the package
is private: a maintainer makes it public in the package settings once the first image exists.

winget is submitted by hand, and only with the maintainers' approval, because it is a public
submission to another project:

1. Download the `package-manifests` artifact of that workflow run and take
   `winget/manifests/h/Hodeitek/HodeiShield/<version>/`.
2. In a fork of [microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs), branch from its
   `master`, add those three files under the same path, and commit
   `New version: Hodeitek.HodeiShield version <version>`.
3. Open a pull request with that title and fill in its template; validate with
   `winget validate --manifest <dir>` where a Windows machine is available.
4. Answer the reviewers there. No long-lived token is stored for this.

### The repository signing key

The APT and DNF repositories are signed with an RSA 4096 OpenPGP key: a certify-only primary key, kept offline by the maintainers and protected by a passphrase, and a sign-only subkey, the only part CI holds (`PACKAGES_GPG_SIGNING_KEY`: the subkey without a passphrase, the primary key as a stub). Both expire two years after creation; `gpg --show-keys packaging/gpg.key` shows the date. Any work with the primary key happens in a throwaway `GNUPGHOME` on a RAM-backed filesystem (`/dev/shm`) with no disk swap active, and ends with `gpgconf --homedir <dir> --kill all` and removing the directory.

**Renewal**, at least 60 days before the expiry. Neither the primary key's fingerprint nor the signing subkey's changes, so the pins in `packaging/repo/keycheck.sh` and the README stay as they are.

1. Import the primary key and the subkey from the offline copy.
2. Extend both: `gpg --quick-set-expire <primary> 2y`, then `gpg --quick-set-expire <primary> 2y <subkey>`. The form `gpg --quick-set-expire <primary> 2y '*'` extends only the subkeys, not the primary, and skips a subkey that has already expired.
3. Export the public key to `packaging/gpg.key` with `GNUPGHOME=<dir> sh packaging/repo/export-public-key.sh <primary> > packaging/gpg.key`, not with a plain `gpg --armor --export`: the script checks what it prints (see the recovery below).
4. Export the subkey again without a passphrase (import `gpg --export-secret-subkeys '<subkey>!'` into a second throwaway `GNUPGHOME`, remove its passphrase with `gpg --change-passphrase <subkey>`, export `'<subkey>!'` again) and replace the `PACKAGES_GPG_SIGNING_KEY` secret with it. The copy in the secret carries the binding signature it was exported with, which is out of date after a renewal. The signing job imports `packaging/gpg.key` after the secret to replace it, so the new `packaging/gpg.key` must be committed before the release that signs; without it gpg refuses to sign once the old expiry date has passed ("Unusable secret key").
5. Commit the new `packaging/gpg.key` and publish a release from that commit. Its `repos` job signs every index again and uploads the new `/gpg.key`; do not re-run `repos` for an older release afterwards, as it would upload that release's key. The new signatures are needed: gpg replaces the old self-signatures when it extends a key, and Sequoia-based verifiers (`sqv`, used by apt on Debian 13) reject a signature made before the new self-signature when they check it against the extended key. RPM package signatures made before the renewal still verify.
6. Say in the release notes that users must refresh their copy of the key before the old expiry date (README, "When the repository key is renewed"). Clients that still hold the old copy reject the signatures made after that date.

**If the signing subkey leaks** (for example the CI secret), or is revoked for any other reason: stop publishing, then recover in this order. Do it when no release is pending: the *Re-sign package repository* workflow shares its concurrency group with the release's packaging jobs, so a pending run of one and a pending run of the other can displace each other. A normal run never replaces a package or a hashed index (only the entry points, the `Packages` files, `gpg.key` and the landing page are rewritten, by design), and every index and RPM signature of the revoked subkey stops counting, so `repos` cannot publish again until the steps below are done: `build.sh` rejects the published `InRelease` (signed by the revoked subkey) and every RPM already in the bucket, and none of them can be replaced by the usual run.

1. **Check the environment's protection rules before setting any secret** (the two `gh api` reads at the end of [its setup](#the-packaging-resign-environment)). **Key custodians** (who hold the primary key; the work happens in a throwaway `GNUPGHOME` on `/dev/shm`, as in the renewal): before anything else, update the offline copy of the primary key with the revocation and the new subkey; delete the leaked secret; add a new signing subkey (`gpg --quick-add-key <primary> rsa4096 sign 2y`); revoke the old one (`gpg --edit-key <primary>`, `key <n>`, `revkey`, reason "Key has been compromised", `save`). Export the new subkey without a passphrase as in renewal step 4, check that it holds exactly one signing subkey, and replace the `PACKAGES_GPG_SIGNING_KEY` secret of the `packaging` environment (the releases) and set the same value in the `packaging-resign` environment (the recovery run).
2. **Export the public key without the revoked subkey.** `rpm` on RHEL and Rocky Linux 8 and 9 does not import a key that carries a revoked subkey. In the same `GNUPGHOME`: `sh packaging/repo/export-public-key.sh <primary> > gpg.key.new`. It exports the minimal key (`--export-options export-minimal`) with every revoked subkey dropped (`--export-filter drop-subkey='fpr = <subkey>'`), and refuses to print anything but one primary key with exactly one signing subkey that is neither revoked nor expired, and no revoked subkey (set `SIGNING_KEY=<new subkey fingerprint>` to also require that it is that subkey). The fingerprint argument must be the full 40 digits. Check it with `gpg --show-keys --with-subkey-fingerprints gpg.key.new`: the primary key, the new signing subkey, and no `[revoked]` line; the fingerprint of the primary key must be the one in the README.
3. **Update `packaging/gpg.key`** with that file in a pull request, together with the pinned signing subkey: `PINNED_SIGNING_SUBKEY` in `packaging/repo/keycheck.sh` and the subkey fingerprint in the README (in groups of four, as gpg prints it). CI's key check (`keycheck.sh packaging/gpg.key README.md`) fails unless all three agree, and the `repos` job and the re-sign run refuse a key whose signing subkey is not the pinned one. The pull request must be reviewed by a maintainer other than its author, who runs the same `gpg --show-keys` and compares the fingerprints; merge it to `main`. Nothing else changes in that pull request.
4. **Dry run.** Check the environment's protection rules before setting any secret, as in step 1. Then set `PACKAGES_S3_ACCESS_KEY_ID` and `PACKAGES_S3_SECRET_ACCESS_KEY` in the `packaging-resign` environment (outside a recovery its secrets must be empty, and the workflow refuses to start while any of them is). Then run the *Re-sign package repository* workflow from `main` with `apply` off (`gh workflow run package-resign.yml --ref main`). Its first job checks that the `packaging-resign` environment exists with the protection rules below and stops the run otherwise; the job that re-signs sits behind that environment, and a maintainer approves the deployment. No input chooses a release: the run lists the packages in the bucket and takes the releases they name (`packaging/repo/bucket-releases.sh`). Each must be a published stable release with all four of its packages there; a draft, a prerelease, any package name of another form, and any published stable release newer than `LAST_RELEASE_WITHOUT_REPOSITORY` in `packaging/repo/live.sh` that is not in the bucket stop the run (a release whose `repos` job has not run yet must be published first). The job summary lists the releases; check them against what the repository should hold before the apply. It downloads each release's packages and verifies them against the release's `SHA256SUMS`, which cosign verifies first with the identity in [docs/verifying-releases.md](docs/verifying-releases.md) (the release workflow, run by the push of that tag), and hands these release assets to `packaging/repo/resign.sh` read-only. Before any package or index is signed, every package in the bucket is compared with them: each `.deb` must be byte for byte a release asset, and each RPM the release's RPM of the same name, epoch, version, release and architecture with the same header and payload digests and the same bytes after its signature header (it differs only by its signature). The run stops there, with nothing signed or uploaded, if a package has no matching asset or differs from it, if a release asset is not in the bucket, or if the pool holds any other file or `rpm/` any other `.rpm`. The published `InRelease` and the old signatures are neither read nor trusted: the RPM packages are signed again from the release assets, never from the bucket's copies, and the APT index is rebuilt from the release `.deb` files. Then `resign.sh` builds the whole repository in a temporary directory and prints, for every RPM, its checksum before and after. Before that, the workflow checks `packaging/gpg.key` with `packaging/repo/keycheck.sh` (exactly one key, the pinned primary fingerprint and the pinned signing subkey, both stated in the README), as the release's `repos` job does. `resign.sh` also refuses to run if the primary key of `packaging/gpg.key` is not the one whose fingerprint the README publishes (it reads it from the README's repository section), if the public key carries a revoked subkey or does not carry exactly one usable signing subkey, the new one, or if the new subkey's signature does not verify against it (that test signature, over a fixed text, is the only one made before the bucket is checked, and is discarded).
5. **Apply.** Run the workflow again from `main` with `apply` on and `confirm` set to the primary key fingerprint published in the README (spaces allowed); one maintainer approves that deployment too. The same checks of the bucket run again; then, before anything is signed, `publish.sh` reads the bucket's versioning, which is what keeps the old RPM objects (nothing is deleted by the run), and refuses unless it reads `Enabled`. Versioning must keep noncurrent versions long enough to roll a re-sign that went wrong back to the previous objects. This is a hard check: the bucket credential must be allowed to read the bucket's versioning (`s3:GetBucketVersioning`), and a credential that cannot makes the run refuse with a message saying so; fix the credential before trying again. Then the RPM packages are signed again from the verified release files and uploaded under their own names, the `.deb` files are not touched, the indexes are regenerated and signed by the new subkey, and the run reads the RPM packages back from the bucket. Until the indexes are uploaded, a client with the new key may fail to install; that is already the state of the repository after the revocation.
6. **Purge the CDN cache** for `/rpm/*/*.rpm` and the entry points (`InRelease`, `Release`, `Release.gpg`, `repomd.xml`, `repomd.xml.asc`, `gpg.key`): the RPM objects had been served with `Cache-Control: immutable` under the same URL.
7. **Verify as a user would.** On Debian or Ubuntu: fetch `https://packages.hodeishield.com/gpg.key` to `/etc/apt/keyrings/hodeishield.asc`, `apt-get update` (no signature warning) and `apt-get install hodeishield`. On Rocky Linux 8 and 9: set the repository up as the README does (the key in a local file, the README's repository file), `dnf clean all`, `dnf install hodeishield`; `dnf` imports the key (compare its fingerprint with the README) and checks the RPM signature and `repomd.xml.asc`. Then publish the next release as usual: `repos` accepts the repository again.
8. Tell users to refresh their copy of the key (README, release notes, and a security advisory if the subkey leaked). The advisory and the README list the fingerprint of the revoked subkey next to the new one. `rpm` keeps the old copy of the key, so give the `rpm -e gpg-pubkey…` instructions of the README ("When the repository key is renewed") together with the new key.
9. **Empty the recovery environment again**: delete the three secrets of `packaging-resign` (`PACKAGES_GPG_SIGNING_KEY`, `PACKAGES_S3_ACCESS_KEY_ID`, `PACKAGES_S3_SECRET_ACCESS_KEY`), so that the signing subkey and the bucket credential live in the `packaging` environment only.

#### The packaging-resign environment

The recovery run has its own environment, separate from the release's `packaging` (which accepts deployments from the release tags and `main`, for the manual run of **Package managers**). It must allow deployments from `main` only, must require a reviewer, and must not let administrators bypass that; the deployment-branch rule, not the workflow's own check of the branch, is what keeps `apply` and the secrets out of reach of other branches. The workflow's first job checks these rules (it reads the environment and its deployment branch policies, which `GITHUB_TOKEN` can do with `actions: read`) and stops the run before the job that uses the environment starts. That order matters: a job that names an environment that does not exist creates it, unprotected. The environment holds the variables `PACKAGES_S3_ENDPOINT`, `PACKAGES_S3_REGION` and `PACKAGES_S3_BUCKET`; its secrets must be empty outside a recovery, are set at steps 1 and 4 of a recovery and deleted at step 9.

One-time setup, by a repository administrator. `<id>` is the numeric id of a reviewer (`gh api users/<login> --jq .id`; a team works too, with `"type": "Team"` and its id):

```sh
printf '%s' '{"reviewers": [{"type": "User", "id": <id>}], "prevent_self_review": true,
  "can_admins_bypass": false,
  "deployment_branch_policy": {"protected_branches": false, "custom_branch_policies": true}}' |
  gh api -X PUT repos/Hodeitek/hodeishield-cli/environments/packaging-resign --input -
gh api -X POST repos/Hodeitek/hodeishield-cli/environments/packaging-resign/deployment-branch-policies \
  -f name=main -f type=branch
gh variable set PACKAGES_S3_ENDPOINT --env packaging-resign --body '<endpoint>'
gh variable set PACKAGES_S3_REGION --env packaging-resign --body '<region>'
gh variable set PACKAGES_S3_BUCKET --env packaging-resign --body '<bucket>'
```

`prevent_self_review` is `true` so that whoever starts a run cannot approve it. A project with a single maintainer must set it to `false`, since that maintainer would otherwise be unable to approve their own run. Check the result: it must show at least one required reviewer, `can_admins_bypass` false, custom branch policies, and the one branch policy `main` of type `branch`:

```sh
gh api repos/Hodeitek/hodeishield-cli/environments/packaging-resign \
  --jq '{can_admins_bypass, deployment_branch_policy, protection_rules}'
gh api repos/Hodeitek/hodeishield-cli/environments/packaging-resign/deployment-branch-policies \
  --jq '.branch_policies[] | {name, type}'
```

The same CI test as for every change to `packaging/repo` (`repo-test.sh`, cases R0 to R26 and L1 to L8) walks through this with throwaway keys: a release signed by a subkey, two subkeys revoked and replaced, `build.sh` refusing the old signatures and the public key that still carries the revoked subkeys, `resign.sh` refusing each unsafe run (among them packages in the bucket that are not the release assets, signed by the revoked subkey or carrying the release's own signature header, an unexpected file, a public key with two signing subkeys, and another primary key that the README does not publish) without changing the bucket, a bucket whose versioning is suspended or was never enabled, a dry run that ignores a published `InRelease` signed by another subkey of the same primary key, one confirmed run that keeps each RPM's header and payload digests, the old RPM versions kept, a new release published that leaves the re-signed RPM objects as they are, the release list read from the bucket (unexpected names, a newline in a name, an empty bucket, a missing release), and apt and dnf (Rocky Linux 9 and 8) installing from the result. It is not meant to be run by hand.

**If the primary key is stolen**: publish its revocation certificate (kept with the offline copy) by importing it with the public key into a throwaway `GNUPGHOME` and exporting the result as `/gpg.key` and `packaging/gpg.key`. A revocation only reaches users who refresh their key, so also announce it (README, release notes, a security advisory) and tell users to remove the key and the repository file. Then create a new key with a new fingerprint, set the secret, update the fingerprints in the README (the only place that states them; the landing page points there) and both pins in `packaging/repo/keycheck.sh`, sign the RPM packages again, and publish a release. Users must check the new fingerprint against the README on GitHub, not against `packages.hodeishield.com` alone. **If the primary key is lost**, it can be neither renewed nor revoked: create a new key well before the expiry and move users to it the same way.

## Closing issues

An issue is closed as soon as the fix reaches `main`, never left open once fixed:

- The commit that fixes an issue says `Closes #N` in its message (not only in the pull request), so
  GitHub closes it when the commit reaches `main`.
- After every release or other merge into `main`, the open issues are reviewed against what landed:
  an issue that is fully fixed is closed with a comment citing the commit and the file or test that
  proves it; one that is partly fixed gets a comment saying what remains; an obsolete one is closed
  with the reason. A security issue is closed only with evidence that it is fixed or not exploitable.
- After a merge into `dev`, the issues the pull request mentions get the same review.

## Design decisions

Significant design choices are written up in [docs/decisions](docs/decisions), one numbered
file each, with a status (Proposed, Accepted, Rejected or Superseded).

## Security testing

The security of the CLI and of its release pipeline is tested on every change and on a schedule.
Scheduled runs use `main`, the default branch, every Monday.

| Test | What it checks | When | Results |
|---|---|---|---|
| `cargo test`, `cargo clippy` (`ci.yml`) | Behaviour, including that credentials are never written, printed or logged | Every pull request and push to `dev` and `main` | The CI run |
| `cargo deny check`, `cargo audit` (`ci.yml`) | Dependencies against the RustSec advisories, and the licence, banned-crate and source policy in `deny.toml` | Every pull request and push to `dev` and `main` | The CI run |
| CodeQL (`security-tests.yml`) | Static analysis of the Rust code and of the workflows, with the `security-extended` queries | Every pull request and push to `dev` and `main`, and weekly | Security tab |
| OSV-Scanner (`security-tests.yml`) | Every dependency in `Cargo.lock` against the OSV database | Every pull request and push to `dev` and `main`, and weekly | Security tab; the run fails |
| actionlint, zizmor (`workflow-lint.yml`) | Workflow mistakes and unsafe patterns: actions not pinned by commit, broad token permissions, template injection, persisted credentials | Every change under `.github`, and weekly | The run fails; zizmor's results also go to the Security tab |
| OpenSSF Scorecard (`scorecard.yml`) | Supply-chain practices of the repository, such as pinning, token permissions, branch protection and signed releases | Every push to `main`, weekly, and when branch protection changes | Security tab, and published on [scorecard.dev](https://scorecard.dev) |
| Dependabot alerts and security updates | Dependencies against the GitHub Advisory Database, which includes RustSec | When an advisory is published or a dependency changes | Security tab, and a pull request when a fixed version exists |
| Repository builder tests (`repo-builder-tests.yml`) | The APT and DNF repository builder refuses forged packages and indexes | Every change to `packaging/repo`, and weekly | The run |
| Repository freshness (`repo-freshness.yml`) | The published APT and DNF repositories are signed and current | Weekly, once `packaging/gpg.key` is committed | An issue labelled `repo-freshness` |
| Release integrity (`release-integrity.yml`) | Release runs, published releases, their files, their Rekor entries (looked up by SHA-256) and the container image signatures match, in both directions ([docs/release-signing.md](docs/release-signing.md#weekly-release-integrity-check)) | Weekly, on demand, and on every change to the check | An issue labelled `release-integrity` |
| Reproducible build (`reproducible-build.yml`) | The Linux binaries of a release, rebuilt from its tag in the pinned build image, are the same bytes as the released ones ([docs/verifying-releases.md](docs/verifying-releases.md#7-rebuild-the-linux-binaries)) | Every published release, and on demand | An issue labelled `reproducible-build` |
| Proxy and TLS (`proxy-tls.yml`) | Proxy and TLS inspection behaviour against a TLS-inspecting proxy | Every change to the CLI, the API client or `Cargo.lock` | The run |
| Dependency review (by hand) | The pins Dependabot does not cover, `cargo outdated`, actions pinned by commit | Monthly | A pull request |

Any actionlint or zizmor finding fails the run; zizmor runs at its pedantic level. A finding that is
accepted instead of fixed is ignored in `.github/zizmor.yml` with a one-line reason.

What happens with the findings:

- The maintainers triage every new alert in the Security tab within 10 business days, the
  first-assessment time in [SECURITY.md](SECURITY.md): they fix it, or dismiss it with the reason
  (false positive, used in tests, will not fix) and a comment saying why.
- A finding that could be exploitable in a released version is handled as a vulnerability report
  under [SECURITY.md](SECURITY.md): a private security advisory, a CVSS v3.1 severity and the fix
  targets there. It is not discussed in a public issue.
- Any other finding that needs work becomes an issue, written as described in [Issues](#issues).
- A failed scheduled run is treated like a failed CI run on `main`: it is looked at before the next
  release.

## Security issues

Do not open a public issue: see [SECURITY.md](SECURITY.md).
