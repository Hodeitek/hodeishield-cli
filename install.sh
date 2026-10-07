#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
#
# Installs the hodeishield CLI on Linux or macOS from a GitHub release, after checking the archive
# against the release's SHA256SUMS and its Sigstore signature (cosign).
#
# Read it before you run it. Usage:
#
#   sh install.sh [--version X.Y.Z] [--dir DIR] [--no-man] [--no-verify]
#
#   --version X.Y.Z  release to install (default: the latest)
#   --dir DIR        where to put the binary (default: /usr/local/bin when writable or run as root,
#                    otherwise ~/.local/bin); man pages go in DIR/../share/man/man1
#   --no-man         do not install the man pages
#   --no-verify      skip the cosign signature check (the SHA256SUMS check always runs). Only for
#                    machines that cannot run cosign; the checksum alone does not prove who built it.
#
# Needs curl, tar and sha256sum or shasum; cosign (https://docs.sigstore.dev) unless --no-verify.

set -eu

REPO="Hodeitek/hodeishield-cli"
WORKFLOW="https://github.com/${REPO}/.github/workflows/release.yml"
ISSUER="https://token.actions.githubusercontent.com"

version=""
dir=""
man=1
verify=1

die() {
  printf 'install.sh: %s\n' "$*" >&2
  exit 1
}

usage() {
  sed -n '9,18s/^# \{0,1\}//p' "$0"
  exit "${1:-0}"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --version) [ $# -ge 2 ] || die "--version needs a value"; version=${2#v}; shift 2 ;;
    --version=*) version=${1#--version=}; version=${version#v}; shift ;;
    --dir) [ $# -ge 2 ] || die "--dir needs a value"; dir=$2; shift 2 ;;
    --dir=*) dir=${1#--dir=}; shift ;;
    --no-man) man=0; shift ;;
    --no-verify) verify=0; shift ;;
    -h | --help) usage 0 ;;
    *) printf 'install.sh: unknown option %s\n\n' "$1" >&2; usage 2 ;;
  esac
done

command -v curl > /dev/null 2>&1 || die "curl is required"
command -v tar > /dev/null 2>&1 || die "tar is required"
if command -v sha256sum > /dev/null 2>&1; then
  sha256() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum > /dev/null 2>&1; then
  sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
  die "sha256sum or shasum is required"
fi
if [ "$verify" -eq 1 ] && ! command -v cosign > /dev/null 2>&1; then
  die "cosign is required to check the signature: install it (https://docs.sigstore.dev/cosign/system_config/installation/) and run this again. To install without the signature check, pass --no-verify."
fi

case "$(uname -s)" in
  Linux)
    case "$(uname -m)" in
      x86_64 | amd64) target="x86_64-unknown-linux-musl" ;;
      aarch64 | arm64) target="aarch64-unknown-linux-musl" ;;
      *) die "no Linux build for $(uname -m); see https://github.com/${REPO}/releases" ;;
    esac
    ;;
  Darwin) target="universal-apple-darwin" ;;
  *) die "this script is for Linux and macOS; on Windows, download the .zip from https://github.com/${REPO}/releases" ;;
esac

if [ -z "$version" ]; then
  latest=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest") ||
    die "could not find the latest release"
  version=${latest##*/}
  version=${version#v}
fi
case "$version" in
  '' | *[!0-9A-Za-z.+-]*) die "unexpected version: $version" ;;
esac

if [ -z "$dir" ]; then
  if [ "$(id -u)" -eq 0 ] || [ -w /usr/local/bin ]; then
    dir=/usr/local/bin
  else
    dir="${HOME}/.local/bin"
  fi
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
name="hodeishield-${version}-${target}"
base="https://github.com/${REPO}/releases/download/v${version}"

printf 'Downloading hodeishield %s for %s…\n' "$version" "$target"
for file in "${name}.tar.gz" "${name}.tar.gz.sigstore.json" SHA256SUMS; do
  curl -fsSL --proto '=https' --tlsv1.2 -o "${tmp}/${file}" "${base}/${file}" ||
    die "could not download ${base}/${file}"
done

expected=$(awk -v f="${name}.tar.gz" '$2 == f || $2 == "*" f { print $1 }' "${tmp}/SHA256SUMS")
[ -n "$expected" ] || die "${name}.tar.gz is not listed in SHA256SUMS"
[ "$(sha256 "${tmp}/${name}.tar.gz")" = "$expected" ] || die "checksum mismatch for ${name}.tar.gz"
printf 'Checksum: OK\n'

if [ "$verify" -eq 1 ]; then
  cosign verify-blob \
    --bundle "${tmp}/${name}.tar.gz.sigstore.json" \
    --certificate-identity "${WORKFLOW}@refs/tags/v${version}" \
    --certificate-oidc-issuer "$ISSUER" \
    --certificate-github-workflow-trigger push \
    "${tmp}/${name}.tar.gz" > /dev/null 2>&1 ||
    die "the Sigstore signature does not verify: do not use this file"
  printf 'Signature: OK (built by %s from tag v%s)\n' "${REPO}" "$version"
else
  printf 'Signature: NOT checked (--no-verify)\n'
fi

tar -xzf "${tmp}/${name}.tar.gz" -C "$tmp"
[ -f "${tmp}/${name}/hodeishield" ] || die "the archive does not contain hodeishield"

mkdir -p "$dir" || die "cannot create $dir (try --dir, or run as a user who can write there)"
cp "${tmp}/${name}/hodeishield" "${tmp}/hodeishield.new"
chmod 0755 "${tmp}/hodeishield.new"
mv -f "${tmp}/hodeishield.new" "${dir}/hodeishield" || die "cannot write ${dir}/hodeishield"
printf 'Installed %s\n' "${dir}/hodeishield"

if [ "$man" -eq 1 ] && [ -d "${tmp}/${name}/man" ]; then
  mandir="$(dirname "$dir")/share/man/man1"
  if mkdir -p "$mandir" 2> /dev/null && cp "${tmp}/${name}/man/"*.1 "$mandir/" 2> /dev/null; then
    printf 'Man pages in %s\n' "$mandir"
  else
    printf 'Man pages not installed: cannot write %s\n' "$mandir"
  fi
fi

# shellcheck disable=SC2016 # the $PATH in the hint is meant literally
case ":${PATH}:" in
  *":${dir}:"*) ;;
  *) printf '\n%s is not on your PATH. Add it, e.g.: export PATH="%s:$PATH"\n' "$dir" "$dir" ;;
esac
"${dir}/hodeishield" --version
