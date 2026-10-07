#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
"""Writes the package-manager files for one published release, from that release's SHA256SUMS.

Usage: package-manifests.py <version> <SHA256SUMS> <out-dir> [<msi-product-code>]

Writes under <out-dir>:
  homebrew/Formula/hodeishield.rb       for Hodeitek/homebrew-hodeishield
  scoop/bucket/hodeishield.json         for Hodeitek/scoop-hodeishield
  winget/manifests/h/Hodeitek/HodeiShield/<version>/*.yaml   for microsoft/winget-pkgs (by hand)

Every URL points at an asset of the release and every hash comes from its SHA256SUMS, so a file
missing from the release is an error. The winget installer is the MSI when the release has one
(its product code must then be given), otherwise the zip with the portable exe inside.

Uses only the standard library.
"""

import json
import pathlib
import re
import sys

REPO = "Hodeitek/hodeishield-cli"
DESCRIPTION = "Read-only command-line client for HodeiShield"


def main():
    version, sums_path, out = sys.argv[1], pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3])
    product_code = sys.argv[4] if len(sys.argv) > 4 else None
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise SystemExit(f"error: {version!r} is not a release version (X.Y.Z)")
    sums = {}
    for line in sums_path.read_text().splitlines():
        digest, _, name = line.partition("  ")
        if re.fullmatch(r"[0-9a-f]{64}", digest) and name:
            sums[name.lstrip("*")] = digest
    base = f"https://github.com/{REPO}/releases/download/v{version}"

    def asset(target, ext):
        name = f"hodeishield-{version}-{target}.{ext}"
        if name not in sums:
            raise SystemExit(f"error: {name} is not in {sums_path}")
        return f"{base}/{name}", sums[name]

    mac_url, mac_sha = asset("universal-apple-darwin", "tar.gz")
    x86_url, x86_sha = asset("x86_64-unknown-linux-musl", "tar.gz")
    arm_url, arm_sha = asset("aarch64-unknown-linux-musl", "tar.gz")
    zip_url, zip_sha = asset("x86_64-pc-windows-msvc", "zip")
    msi_name = f"hodeishield-{version}-x86_64-pc-windows-msvc.msi"
    has_msi = msi_name in sums
    if has_msi and not (product_code and re.fullmatch(r"\{[0-9A-F-]{36}\}", product_code)):
        raise SystemExit("error: the release has an MSI, so its product code ({XXXXXXXX-...}) is required")

    formula = out / "homebrew" / "Formula" / "hodeishield.rb"
    formula.parent.mkdir(parents=True, exist_ok=True)
    formula.write_text(f'''# Written by the release workflow of https://github.com/{REPO}; do not edit by hand.
class Hodeishield < Formula
  desc "{DESCRIPTION}"
  homepage "https://hodeishield.com"
  license "Apache-2.0"

  # One universal binary serves both Mac architectures.
  on_macos do
    on_intel do
      url "{mac_url}"
      sha256 "{mac_sha}"
    end
    on_arm do
      url "{mac_url}"
      sha256 "{mac_sha}"
    end
  end

  on_linux do
    on_intel do
      url "{x86_url}"
      sha256 "{x86_sha}"
    end
    on_arm do
      url "{arm_url}"
      sha256 "{arm_sha}"
    end
  end

  def install
    bin.install "hodeishield"
    man1.install Dir["man/*.1"]
    generate_completions_from_executable(bin/"hodeishield", "completions")
  end

  test do
    assert_match version.to_s, shell_output("#{{bin}}/hodeishield --version")
  end
end
''')

    manifest = out / "scoop" / "bucket" / "hodeishield.json"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(json.dumps({
        "version": version,
        "description": DESCRIPTION,
        "homepage": "https://hodeishield.com",
        "license": "Apache-2.0",
        "architecture": {"64bit": {"url": zip_url, "hash": zip_sha}},
        "bin": "hodeishield.exe",
        "checkver": {"github": f"https://github.com/{REPO}"},
        "autoupdate": {
            "architecture": {"64bit": {
                "url": f"https://github.com/{REPO}/releases/download/v$version/hodeishield-$version-x86_64-pc-windows-msvc.zip"
            }},
            "hash": {"url": "$baseurl/SHA256SUMS"},
        },
    }, indent=4) + "\n")

    winget = out / "winget" / "manifests" / "h" / "Hodeitek" / "HodeiShield" / version
    winget.mkdir(parents=True, exist_ok=True)
    head = f"PackageIdentifier: Hodeitek.HodeiShield\nPackageVersion: {version}\n"
    (winget / "Hodeitek.HodeiShield.yaml").write_text(
        "# yaml-language-server: $schema=https://aka.ms/winget-manifest.version.1.12.0.schema.json\n\n"
        + head + "DefaultLocale: en-US\nManifestType: version\nManifestVersion: 1.12.0\n")
    if has_msi:
        msi_url = f"{base}/{msi_name}"
        installer = (f"InstallerType: wix\nScope: machine\nUpgradeBehavior: install\n"
                     f"InstallModes:\n- interactive\n- silent\n- silentWithProgress\n"
                     f"Commands:\n- hodeishield\nInstallers:\n- Architecture: x64\n"
                     f"  InstallerUrl: {msi_url}\n  InstallerSha256: {sums[msi_name].upper()}\n"
                     f"  ProductCode: '{product_code}'\n  AppsAndFeaturesEntries:\n"
                     f"  - ProductCode: '{product_code}'\n"
                     f"    UpgradeCode: '{{32B34E35-7A3F-422A-AC44-59204CD0D59D}}'\n")
    else:
        installer = (f"InstallerType: zip\nNestedInstallerType: portable\nNestedInstallerFiles:\n"
                     f"- RelativeFilePath: hodeishield.exe\n  PortableCommandAlias: hodeishield\n"
                     f"Commands:\n- hodeishield\nInstallers:\n- Architecture: x64\n"
                     f"  InstallerUrl: {zip_url}\n  InstallerSha256: {zip_sha.upper()}\n")
    (winget / "Hodeitek.HodeiShield.installer.yaml").write_text(
        "# yaml-language-server: $schema=https://aka.ms/winget-manifest.installer.1.12.0.schema.json\n\n"
        + head + installer + "ManifestType: installer\nManifestVersion: 1.12.0\n")
    (winget / "Hodeitek.HodeiShield.locale.en-US.yaml").write_text(
        "# yaml-language-server: $schema=https://aka.ms/winget-manifest.defaultLocale.1.12.0.schema.json\n\n"
        + head + f"""PackageLocale: en-US
Publisher: Hodeitek S.L.
PublisherUrl: https://hodeishield.com
PublisherSupportUrl: https://github.com/{REPO}/issues
PackageName: HodeiShield CLI
PackageUrl: https://github.com/{REPO}
License: Apache-2.0
LicenseUrl: https://github.com/{REPO}/blob/main/LICENSE
Copyright: Copyright 2026 Hodeitek S.L.
ShortDescription: {DESCRIPTION}
Description: hodeishield reads vendors, alerts, risks, compliance posture, evidence and endpoints from the HodeiShield /v1 API, as tables, CSV or the API's own JSON, for people and for scripts.
Moniker: hodeishield
Tags:
- cli
- compliance
- cybersecurity
- risk-management
- supply-chain
- third-party-risk
ReleaseNotesUrl: https://github.com/{REPO}/releases/tag/v{version}
Documentations:
- DocumentLabel: Verifying releases
  DocumentUrl: https://github.com/{REPO}/blob/main/docs/verifying-releases.md
ManifestType: defaultLocale
ManifestVersion: 1.12.0
""")
    print(f"wrote the Homebrew formula, the Scoop manifest and the winget manifests "
          f"({'MSI' if has_msi else 'zip'}) for {version}")


if __name__ == "__main__":
    main()
