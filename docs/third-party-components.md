# Third-party components

This is how the CLI chooses, monitors and fixes the third-party components it is built from, and
how a vulnerability found in one of them is passed to its maintainers. It is the due diligence of
the Cyber Resilience Act (Regulation (EU) 2024/2847), Article 13(5) and (6).

The components are:

- the Rust crates in `Cargo.lock`, compiled into the binary;
- the GitHub Actions used by the workflows in `.github/workflows`;
- the tools the workflows download and run, pinned by version and SHA-256, and the container base
  images, pinned by digest ([CONTRIBUTING.md](../CONTRIBUTING.md#dependency-updates)).

## Adding a dependency

A pull request that adds a crate to a `Cargo.toml`, a new action to a workflow or a new tool to the
release pipeline says in its description how the new component meets each of these criteria:

- **Need.** The standard library or a component already in use cannot do the job with reasonable
  effort.
- **Maintenance.** The component has a release or a maintainer response in the last twelve months,
  more than one maintainer or an organisation behind it where possible, and a way to report a
  vulnerability (a security policy, private vulnerability reporting, or a contact address).
- **Security history.** Its advisories in the RustSec and GitHub advisory databases, and how quickly
  they were fixed. A component with an open advisory is not added.
- **Licence and source.** The licence is in the `[licenses] allow` list of `deny.toml`, and the
  crate comes from crates.io. Adding a licence or a source changes `deny.toml` in the same pull
  request and says why.
- **Size.** The crates it adds to `Cargo.lock` (`cargo tree` before and after), with default
  features turned off where they are not needed. A component that brings many new crates for a small
  job needs a stronger reason.
- **Code that runs at build time.** Build scripts and procedural macros are named, since they run on
  the build machine, including in the release workflow.
- **Pinning.** Crates are locked in `Cargo.lock` and built with `--locked`. Actions are pinned by
  full commit SHA, and tools by version and SHA-256.

A maintainer reviews the pull request against this list and merges it only when the description
answers every point. The same review applies to a component that a Dependabot update adds to
`Cargo.lock`: before merging the update, a maintainer looks for new crates in its `Cargo.lock` diff
and checks them. A removed component needs no review beyond the usual one.

## How the checks fit together

| Check | What it covers | When |
|---|---|---|
| `cargo deny check` (`ci.yml`) | RustSec advisories, licences, sources, wildcard versions (`deny.toml`) | Every pull request and every push to `dev` and `main` |
| `cargo audit` (`ci.yml`) | RustSec advisories, with the same accepted list as `cargo deny` | Every pull request and every push to `dev` and `main` |
| Release gate (`release.yml`, `advisories` job) | Both of the above on the tagged commit; nothing is signed or published if it fails | Every release |
| OSV-Scanner (`security-tests.yml`) | Every crate in `Cargo.lock` against the OSV database | Every pull request and every push to `dev` and `main`, and weekly |
| Dependabot alerts and security updates | Crates against the GitHub Advisory Database | When an advisory is published |
| Dependabot version updates (`.github/dependabot.yml`) | Crates, actions and the container base image, for versions at least seven days old; no major versions | Weekly |
| Dependency review, by hand | The pins Dependabot does not cover, `cargo audit`, `cargo outdated`, actions pinned by commit | Monthly |

The automated checks find a known vulnerability on the next change, on the weekly run or when the
advisory is published, whichever comes first. The monthly review catches what they do not cover. The
details of each check are in [CONTRIBUTING.md](../CONTRIBUTING.md#dependency-updates) and
[Security testing](../CONTRIBUTING.md#security-testing).

## When a component has a vulnerability

1. **Assess it.** Within the triage time of [Security testing](../CONTRIBUTING.md#security-testing)
   (10 business days), a maintainer checks whether the CLI is affected: whether the affected code is
   reachable from the CLI, and whether its conditions can occur in the way the CLI uses the component.
   Until it is shown otherwise, it is treated as exploitable.
2. **Fix it.** Update the component to a fixed version, or replace it, or remove it. When no fixed
   version exists and the CLI is affected, change the CLI so the affected code is not used, or carry
   a fix (below).
3. **Release.** A release is not published while the advisory is unaddressed, unless it is accepted
   with a written reason and a review date
   ([Known vulnerabilities at release](../CONTRIBUTING.md#known-vulnerabilities-at-release)).
4. **Tell the users.** If a released version of the CLI is exploitable, the vulnerability is handled
   as a vulnerability in the CLI: a security advisory in this repository, with the fix targets and
   notices of [SECURITY.md](../SECURITY.md).

## Reporting a vulnerability to the component's maintainers

This applies to a vulnerability that the maintainers of this repository find, or that is reported to
them, and that is not yet known to the component's maintainers: no published advisory, no open
report.

- **Report it privately**, through the component's own security policy: its `SECURITY.md`, private
  vulnerability reporting on its repository, or its security contact. Include the affected versions,
  how to reproduce it and, where known, the fix. Do not open a public issue.
- **If there is no channel**, or no answer within 14 days, report it to the RustSec advisory database
  for a crate, or to GitHub's advisory database for an action, following their reporting
  instructions.
- **Disclosure** follows the coordinated disclosure of [SECURITY.md](../SECURITY.md#coordinated-disclosure):
  the vulnerability stays confidential until the component's advisory is published or 90 days have
  passed, unless it is already being exploited.
- **Share the fix.** If the maintainers of this repository fix the vulnerability, they send the
  change to the component's maintainers: in the private report while it is confidential, and as a
  pull request once it is public, under the component's licence. A patched copy used by the CLI in
  the meantime (`[patch.crates-io]` in `Cargo.toml`, which `deny.toml` must allow explicitly) is
  removed once a fixed version is released.

### Record of reports

While a report is confidential, it is recorded in a draft security advisory of this repository,
which only the maintainers can see: the component, the date and channel of the report, the answers,
and the fix shared. If the CLI is not affected, the draft is closed without publishing it once the
entry below is added.

Once the vulnerability is public, it gets an entry in this table.

| Reported | Component | Affected versions | Report or advisory | Fix shared |
|---|---|---|---|---|

No vulnerability has been reported to a component's maintainers yet.
