# Technical documentation

This document is the index of the technical documentation of `hodeishield` that Article 13 of the
Cyber Resilience Act, [Regulation (EU) 2024/2847](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng),
asks the manufacturer to draw up, as set out in Annex VII. It follows the eight items of Annex VII
in order. For each item it points to the file in this repository that holds the information, and
says plainly what does not apply or is not available yet. Every statement about the product names
the file that backs it, so that a reader can check it.

The manufacturer is Hodeitek S.L., Markole 17, 20550 Aretxabaleta, Gipuzkoa, Spain
([NOTICE](../NOTICE), [user-information.md](user-information.md#manufacturer-and-contact)). The
product is HodeiShield CLI; its command is `hodeishield`.

Each release keeps the copy of this document that applies to it, in that release's tag:
`https://github.com/Hodeitek/hodeishield-cli/blob/v<version>/docs/technical-documentation.md`.

## Classification and conformity route

- **Product.** `hodeishield` is a product with digital elements (Article 3(1)): software that is
  placed on the market and that connects to a remote data processing solution, the HodeiShield
  service ([user-information.md](user-information.md#intended-purpose)).
- **Category.** It is in the default category. Under Article 7(1), a product is important only if
  its core functionality is one of those listed in Annex III (class I or class II), and critical
  only if it is one of those in Annex IV. The core functionality of `hodeishield` is to read one
  organisation's data from the HodeiShield API, from a terminal or a script
  ([risk-assessment.md](risk-assessment.md#intended-purpose-and-conditions-of-use)). It is a
  read-only API client: it is not, for example, a password manager, a VPN, a SIEM or an identity
  management system, and no other entry of Annex III or Annex IV describes it. The technical
  descriptions of those categories are in Commission Implementing Regulation (EU) 2025/2392.
- **Conformity assessment.** For a product in the default category, the manufacturer uses the
  internal control procedure, module A (Article 32(1)(a); Annex VIII, Part I). No notified body is
  involved. The manufacturer draws up this technical documentation, ensures that the design,
  development and vulnerability handling meet the requirements of Annex I, and draws up the EU
  declaration of conformity.
- **Review of the category.** The classification is checked again when the product changes
  substantially, or when the lists in Annex III and Annex IV or the implementing acts that describe
  them change (see [Procedure](#procedure-declaration-and-ce-marking)).

## Dates

- The obligations of Article 14 (reporting of actively exploited vulnerabilities and severe
  incidents) apply from 11 September 2026.
- The obligations of Article 13 and Annex I, the conformity assessment and the CE marking apply from
  11 December 2027 (Article 71(2)).
- No declaration of conformity is signed and no CE marking is affixed before 11 December 2027. The
  [template of the declaration](declaration-of-conformity.md) is prepared now.

## 1. General description of the product

| Annex VII, item 1 | Where it is |
|---|---|
| (a) Intended purpose | [user-information.md](user-information.md#intended-purpose) and [risk-assessment.md](risk-assessment.md#intended-purpose-and-conditions-of-use): a read-only command-line client for the public `/v1` API of HodeiShield |
| (b) Versions of the software that affect compliance with the essential requirements | Versions follow [Semantic Versioning](https://semver.org/); each release is tagged `v<version>`, and the version is in `Cargo.toml` and printed by `hodeishield --version` ([user-information.md](user-information.md#product)). The notes of each release are in [CHANGELOG.md](../CHANGELOG.md). The risk assessment states the version it describes ([risk-assessment.md](risk-assessment.md#review)) |
| (c) Photographs or illustrations of external features, marking and internal layout | Not applicable: the product is software only |
| (d) User information and instructions (Annex II) | [user-information.md](user-information.md): manufacturer and contact, point of contact for vulnerabilities, intended purpose, secure use, support period, updates, decommissioning and the SBOM. The address of the declaration of conformity is in [Product](user-information.md#product) |

Releases before 0.4.0 were published before the user information existed, and releases before the
first one that contains this file were published before this documentation existed.

## 2. Design, development, production and vulnerability handling

### (a) Design and development

- **System architecture.** `hodeishield` is a short-lived process on the user's machine, without a
  server part, daemon or plug-in interface ([risk-assessment.md](risk-assessment.md#intended-purpose-and-conditions-of-use)).
  The repository has two crates and a build tool ([README.md](../README.md#repository-layout)):
  `hodeishield-cli`, the binary, and `hodeishield-api`, a Rust client for `/v1` generated from the
  OpenAPI document vendored in [openapi/v1.json](../openapi/README.md); `xtask` is the generator and
  is not shipped. The CLI calls the client; the client builds the requests, authenticates, retries
  and limits the size of responses ([CONTRIBUTING.md](../CONTRIBUTING.md#design)).
- **Assets, interfaces and data.** [risk-assessment.md](risk-assessment.md#assets), the
  [attack surface](risk-assessment.md#attack-surface) and
  [data minimisation](risk-assessment.md#data-minimisation).
- **Design decisions.** [docs/decisions](decisions) and the decisions in
  [risk-assessment.md](risk-assessment.md#decisions). Decision record 0001 is a proposal: nothing in
  it is decided or implemented.
- **Development rules.** [CONTRIBUTING.md](../CONTRIBUTING.md#development): the Rust toolchain is
  pinned in `rust-toolchain.toml`, `unsafe` code is denied in the workspace (`Cargo.toml`,
  `[workspace.lints.rust]`) and allowed only in `std_handles.rs` (Windows), changes reach `main` only through pull requests with passing checks and
  signed commits ([release-signing.md](release-signing.md#who-may-change-them)).
- **Components.** The dependencies are fixed in `Cargo.lock`, and the components of each release are
  listed in its SBOM (item 8). How they are chosen, monitored and fixed is in
  [third-party-components.md](third-party-components.md) (Article 13(5)). Drawings and schemes other than the above are not kept: the product
  has no hardware.

### (b) Vulnerability handling

| Element | Where it is |
|---|---|
| Software bill of materials | A CycloneDX SBOM for each archive, signed, and for the container image as an attestation ([user-information.md](user-information.md#software-bill-of-materials)) |
| Identification and monitoring of vulnerabilities and components | [risk-assessment.md](risk-assessment.md#requirements-of-annex-i-part-ii), point (1), and [CONTRIBUTING.md](../CONTRIBUTING.md#security-testing) |
| Vulnerabilities in third-party components | Assessment, fix and release rule, reporting to the component's maintainers with any fix, and the record of reports ([third-party-components.md](third-party-components.md#when-a-component-has-a-vulnerability); Article 13(6)) |
| Coordinated vulnerability disclosure policy | [SECURITY.md](../SECURITY.md#coordinated-disclosure) |
| Point of contact for reports | Private reporting on GitHub and security@hodeitek.com; `security.txt` ([.well-known/security.txt](../.well-known/security.txt); [SECURITY.md](../SECURITY.md#reporting-a-vulnerability)) |
| What happens after a report, fix targets and advisories | [SECURITY.md](../SECURITY.md#what-happens-after-you-report), [fix targets](../SECURITY.md#severity-and-fix-targets) and [advisories](../SECURITY.md#how-advisories-are-published); the advisory template is [security-advisory-template.md](security-advisory-template.md) |
| Secure distribution of updates | Signed releases with checksums, Sigstore signatures and SLSA provenance ([verifying-releases.md](verifying-releases.md), [release-signing.md](release-signing.md)); the update command of each channel is in [user-information.md](user-information.md#updating). The CLI does not update itself ([risk-assessment.md](risk-assessment.md#no-automatic-updates)) |

Not yet available: the procedure for the reports of Article 14 to the CSIRT and ENISA, which is not
documented in this repository yet. The APT and DNF repositories are not published yet; their signing key is described
in [release-signing.md](release-signing.md#package-repository-key).

### (c) Production and monitoring

The product is built from a tagged commit by [release.yml](../.github/workflows/release.yml), which
builds with `--locked`, signs, makes the SBOM and the provenance, and publishes a draft release.
[container-image.yml](../.github/workflows/container-image.yml) and
[package-managers.yml](../.github/workflows/package-managers.yml) publish the container image and
the Homebrew, Scoop, APT and DNF channels when a release is published. Who may change these, and how
the pipeline is checked, is in [release-signing.md](release-signing.md#who-may-change-them) and
[release-signing.md](release-signing.md#weekly-release-integrity-check). The checks that run
weekly after the release are listed under [Test reports](#6-test-reports).

## 3. Cybersecurity risk assessment

[risk-assessment.md](risk-assessment.md) is the assessment of Article 13(2) to (4): assets, threats
T1 to T13 and their controls, how each requirement of Annex I, Part I and Part II is met or why it
does not apply, the decisions behind them, and the residual risks. It is reviewed as described in
[Review](risk-assessment.md#review).

## 4. Support period

The information used to determine the support period (Article 13(8)) is this section and
[SECURITY.md](../SECURITY.md#supported-versions), which is the commitment made to users.

- **Period.** From 1.0.0, each major version receives security fixes for five years, counted from
  the release of its first version. Until 1.0.0 is released, the 0.x series has no end-of-support
  date and security fixes go into the latest 0.x release. The end date of version 1 is set when
  1.0.0 is released and is then published in SECURITY.md and in the release notes.
- **Rationale.**
  - Expected time in use. `hodeishield` is a command-line client for a SaaS service that
    organisations use. It is installed on workstations, servers and CI runners
    ([risk-assessment.md](risk-assessment.md#intended-purpose-and-conditions-of-use)), where it can be
    part of scripts and pipelines that are expected to run for as long as the organisation uses the
    service.
  - Minimum. Article 13(8) requires a support period of at least five years, unless the product is
    expected to be used for less. Nothing in the intended purpose points to a shorter use.
  - Security fixes stay available while a version is supported, even after a HodeiShield
    subscription ends: every release is a public download, and installing or updating the CLI never
    requires a subscription ([SECURITY.md](../SECURITY.md#supported-versions)).
- **How end of support is announced.** Twelve months before it ends, in SECURITY.md, in the
  security notice block of the README and in the release notes ([SECURITY.md](../SECURITY.md#supported-versions)).

This rationale is open to review before 1.0.0 is released, because the support period starts then.

## 5. Standards, specifications and certification schemes applied

- **Harmonised standards.** No harmonised standard for the essential requirements of the Cyber
  Resilience Act is cited in the Official Journal of the European Union at the time of writing.
  None is applied. No common specification or European cybersecurity certification scheme is
  applied either.
- **Solutions adopted.** The requirements of Annex I, Part I and Part II are met by the measures in
  [risk-assessment.md](risk-assessment.md#requirements-of-annex-i-part-i), point by point, with the
  reason when a point does not apply.
- **Other specifications the project follows,** as far as they can be seen in this repository:

| Specification | Used for | Where |
|---|---|---|
| [Semantic Versioning](https://semver.org/) | Version numbers and the scripting surface | [README.md](../README.md#stability), [CHANGELOG.md](../CHANGELOG.md) |
| [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) | The release notes | [CHANGELOG.md](../CHANGELOG.md) |
| [CycloneDX](https://cyclonedx.org) | The SBOM of each release | [user-information.md](user-information.md#software-bill-of-materials) |
| [Sigstore](https://www.sigstore.dev/) signatures | Signing archives, packages, checksums, SBOMs and the container image | [verifying-releases.md](verifying-releases.md) |
| [SLSA](https://slsa.dev) provenance | Build provenance of the release archives | [verifying-releases.md](verifying-releases.md) |
| RFC 9116 (`security.txt`) | Machine-readable contact for vulnerabilities | [SECURITY.md](../SECURITY.md#reporting-a-vulnerability) |
| OpenAPI 3.1 | The description of the `/v1` API from which the client is generated | [openapi/README.md](../openapi/README.md) |
| OpenPGP | The key of the APT and DNF repositories, once they are published | [release-signing.md](release-signing.md#package-repository-key) |

## 6. Test reports

The reports of the tests are the runs of the workflows in
[.github/workflows](../.github/workflows) on GitHub. Each release's CI runs, on its tag and on the
commits before it, are its test reports. What each test checks, when it runs and where the result is
are in [CONTRIBUTING.md](../CONTRIBUTING.md#security-testing). The workflows are:

| Workflow | What it does |
|---|---|
| [ci.yml](../.github/workflows/ci.yml) | Format, lint, code generation check, tests, `cargo deny`, `cargo audit`, the install script, the changelog and the commit messages, on every pull request and push to `dev` and `main` |
| [security-tests.yml](../.github/workflows/security-tests.yml) | CodeQL analysis of the Rust code and of the workflows, and OSV-Scanner on `Cargo.lock`, on every change and weekly |
| [proxy-tls.yml](../.github/workflows/proxy-tls.yml) | Behaviour behind a TLS-inspecting proxy, on changes to the CLI, the API client or `Cargo.lock` |
| [workflow-lint.yml](../.github/workflows/workflow-lint.yml) | actionlint and zizmor on the workflows, on every change under `.github` and weekly |
| [scorecard.yml](../.github/workflows/scorecard.yml) | OpenSSF Scorecard of the repository, on every push to `main` and weekly |
| [openapi-sync.yml](../.github/workflows/openapi-sync.yml) | Weekly check that the vendored OpenAPI document matches the one the API publishes |
| [repo-builder-tests.yml](../.github/workflows/repo-builder-tests.yml) | The APT and DNF repository builder refuses forged packages and indexes |
| [release.yml](../.github/workflows/release.yml) | Builds, tests the MSI, signs and publishes a release, with its SBOM and provenance |
| [container-image.yml](../.github/workflows/container-image.yml) | Builds, publishes and signs the container image when a release is published |
| [package-managers.yml](../.github/workflows/package-managers.yml) | Publishes the Homebrew, Scoop, APT and DNF channels when a release is published; a manual run from `main` republishes APT and DNF for the latest release |
| [release-integrity.yml](../.github/workflows/release-integrity.yml) | Weekly check that release runs, published files, signature log entries and image signatures match |
| [repo-freshness.yml](../.github/workflows/repo-freshness.yml) | Weekly check that the APT and DNF repositories are signed and current |

Not available: a test report from a third party. The tests are the manufacturer's own.

## 7. EU declaration of conformity

The [template](declaration-of-conformity.md) follows Annex V. No declaration has been issued. From
11 December 2027, each release has its issued declaration in its tag, at
`https://github.com/Hodeitek/hodeishield-cli/blob/v<version>/docs/declaration-of-conformity.md`.

## 8. Software bill of materials

Each release publishes a CycloneDX SBOM for each archive, and the container image carries one as a
signed attestation ([user-information.md](user-information.md#software-bill-of-materials)). The
SBOM is public, so it is available to a market surveillance authority without a request.

## Procedure: declaration and CE marking

- **Who signs.** A legal representative of Hodeitek S.L. signs the EU declaration of conformity, for
  and on behalf of the manufacturer. The declaration is issued under the sole responsibility of the
  manufacturer.
- **Before signing.** The signatory checks that this documentation is up to date for the release,
  that the [risk assessment](risk-assessment.md) has been reviewed for it, and that the CI runs
  of the release tag passed (item 6). Module A is internal control: the manufacturer decides on its
  own account that the product meets the requirements of Annex I.
- **When the declaration is reviewed.** It is reviewed and issued again for each release, and
  whenever the product is substantially modified (Article 3(30)), even between releases. The
  technical documentation is updated with each release.
- **The declaration of a release** is the file `docs/declaration-of-conformity.md` in that
  release's tag, with the fields of the template filled in. A simplified declaration (Annex VI) may
  be used and then points to the same address.
- **CE marking.** The product is software with no physical form or packaging, so the CE marking is
  shown digitally (Article 30(1)): on the EU declaration of conformity, and in the README and the
  release notes of the release it applies to. The marking follows the general principles of
  Article 30 of Regulation (EC) No 765/2008. Nothing is marked before 11 December 2027.
- **Records.** The version, place and date of issue, and the name and function of the signatory are
  written in the declaration.

## Retention

The technical documentation and the declaration of each release are kept for at least ten years
after the product is placed on the market, or for the support period, whichever is longer
(Article 13(13)). The support period is in [item 4](#4-support-period).

The method:

- the copy of the repository in each release's tag on GitHub, which holds this documentation and the
  declaration as they were for that release, and the release's assets (archives, packages, SBOMs,
  signatures, provenance and `SHA256SUMS`);
- an archive of each release, with its source and documentation, kept by the manufacturer.
