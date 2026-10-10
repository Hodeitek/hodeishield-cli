#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
#
# Checks that the APT and DNF repositories served at packages.hodeishield.com are signed by the
# repository key and offer the latest release. The indexes carry no Valid-Until, so a stale index that
# was once validly signed would still verify: this finds one being served, it does not prevent it.
#
#   freshness.sh <base-url> <expected-version> <public-key>
#
# <base-url> is the root of the repositories (https://packages.hodeishield.com), <expected-version>
# the version of the latest release (0.2.1, no leading "v") and <public-key> the ASCII-armored public
# key (packaging/gpg.key).
#
# Environment:
#   FRESHNESS_ALLOW_HTTP  1 allows a plain http base URL, which is only for testing against a local server
#   FRESHNESS_RETRIES     retries of a failed download (default 3)
#
# Exit status: 0 when both repositories verify and offer exactly the expected version; 3 when everything
# verifies but a repository offers an older version than expected (the index is stale, or the new
# release is not published there yet); 5 when everything verifies and is current but the repository key
# or its signing subkey expires within 60 days (a warning, to renew it in time); 1 for anything else. Failing closed: a download that fails, an
# unreadable or unsigned index, a hash that does not match or a version that cannot be read is never a pass.
#
# Only what a signature covers is believed. The APT index is a single clear-signed message and only the
# text that gpgv writes is read; each Packages file is fetched by hash and compared with the hash in
# that text. For DNF, repomd.xml is verified with its detached signature and names the hash and the
# location of primary.xml.gz. The newest hodeishield version in each index must be the expected one.
# A signature counts only when gpgv reports it good and made by the repository key: an expired or
# revoked key, or an expired signature, is a failure although gpgv exits 0 (see sigcheck.sh).
# Uses curl, gpgv, gpg, gzip, awk, sed, grep and sort (GNU, for -V).

set -eu

base=$1
expected=$2
key=$3
retries=${FRESHNESS_RETRIES:-3}
status=0
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=sigcheck.sh
. "$here/sigcheck.sh"

die() {
  printf 'freshness.sh: %s\n' "$*" >&2
  exit 1
}

case $expected in
  *[!0-9A-Za-z.+~]* | '') die "the expected version is not a version: $expected" ;;
esac
case $retries in
  *[!0-9]* | '') die "FRESHNESS_RETRIES is not a number" ;;
esac
proto='=https'
if [ "${FRESHNESS_ALLOW_HTTP:-}" = 1 ]; then proto='=http,https'; fi
case $base in
  http://* | https://*) ;;
  *) die "the base URL is not an http(s) URL: $base" ;;
esac
base=${base%/}
[ -s "$key" ] || die "the public key $key is missing or empty"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
# gpg needs a home, even to dearmor.
GNUPGHOME=$work
export GNUPGHOME
gpg --batch --quiet --dearmor --output "$work/key.gpg" "$key" || die "cannot read the public key $key"
[ -s "$work/key.gpg" ] || die "the public key $key holds no key"
primary=$(gpg --batch --with-colons --show-keys "$key" | awk -F: '$1 == "fpr" { print $10; exit }')
[ -n "$primary" ] || die "cannot read the fingerprint of the public key $key"
stamp=$(date +%s)

# Downloads $base/<path> to <dest>. The CDN's copy must not be what is judged, so the request asks
# for no cached copy and carries a query that is new on every run. Redirects are not followed.
fetch() {
  curl --fail --silent --show-error --proto "$proto" --connect-timeout 10 --max-time 120 \
    --retry "$retries" --retry-delay 2 --retry-all-errors \
    --header 'Cache-Control: no-cache' --header 'Pragma: no-cache' \
    --output "$2" "$base/$1?nocache=$stamp" || die "cannot download $base/$1"
  [ -s "$2" ] || die "$base/$1 is empty"
}

# Compares the newest version found with the one expected, and says which repository it is about.
# $1 repository, $2 the versions found (one per line), $3 the expected one.
judge() {
  [ -n "$2" ] || die "$1: no hodeishield package in the index"
  newest=$(printf '%s\n' "$2" | LC_ALL=C sort -V | tail -n 1)
  case $newest in
    *[!0-9A-Za-z.+~:-]*) die "$1: cannot read the newest version" ;;
  esac
  if [ "$newest" = "$3" ]; then
    printf '%s: serves %s, as expected\n' "$1" "$newest"
    return
  fi
  if [ "$(printf '%s\n%s\n' "$newest" "$3" | LC_ALL=C sort -V | head -n 1)" = "$newest" ]; then
    printf '%s: expected %s, serves %s\n' "$1" "$3" "$newest"
    status=3
  else
    die "$1: serves $newest, newer than the expected $3"
  fi
}

# --- APT -------------------------------------------------------------------------------------------
fetch apt/dists/stable/InRelease "$work/InRelease"
# A single clear-signed message and nothing around it (the same check as build.sh), and only the
# signed text is read.
if ! {
  [ "$(head -n 1 "$work/InRelease")" = '-----BEGIN PGP SIGNED MESSAGE-----' ] &&
    [ "$(tail -n 1 "$work/InRelease")" = '-----END PGP SIGNATURE-----' ] &&
    [ "$(grep -c '^-----BEGIN PGP' "$work/InRelease")" = 2 ] &&
    [ "$(grep -c '^-----END PGP' "$work/InRelease")" = 1 ]
}; then
  die "InRelease is not a single signed message"
fi
sig_ok "$work/key.gpg" "$primary" --output "$work/Release" "$work/InRelease" ||
  die "InRelease does not verify against the repository key"
[ -s "$work/Release" ] || die "InRelease holds no text"
for arch in amd64 arm64; do
  file=main/binary-$arch/Packages
  entry=$(awk -v f="$file" '/^[^ ]/ { s = ($0 == "SHA256:"); next } s && $3 == f { print $1, $2 }' "$work/Release")
  # Exactly one "<sha256> <size>" for the file.
  [ "$(printf '%s\n' "$entry" | grep -c .)" = 1 ] || die "InRelease does not list $file once"
  hash=${entry%% *}
  size=${entry#* }
  case $hash in *[!0-9a-f]* | '') hash=none ;; esac
  [ ${#hash} = 64 ] || die "InRelease gives no SHA256 for $file"
  case $size in *[!0-9]* | '') die "InRelease gives no size for $file" ;; esac
  # By hash: the copy that this signed InRelease names, whichever Packages is current in the meantime.
  fetch "apt/dists/stable/main/binary-$arch/by-hash/SHA256/$hash" "$work/Packages.$arch"
  [ "$(sha256sum < "$work/Packages.$arch" | cut -d' ' -f1)" = "$hash" ] ||
    die "$file does not match the SHA256 in InRelease"
  [ "$(stat -c %s "$work/Packages.$arch")" = "$size" ] || die "$file does not match the size in InRelease"
  versions=$(awk -v a="$arch" 'BEGIN { RS = ""; FS = "\n" }
    {
      p = v = r = ""
      for (i = 1; i <= NF; i++) {
        if ($i ~ /^Package: /) p = substr($i, 10)
        else if ($i ~ /^Version: /) v = substr($i, 10)
        else if ($i ~ /^Architecture: /) r = substr($i, 15)
      }
      if (p == "hodeishield" && r == a) print v
    }' "$work/Packages.$arch")
  # nfpm names the package <version>-1.
  judge "APT ($arch)" "$versions" "$expected-1"
done

# --- DNF -------------------------------------------------------------------------------------------
for arch in x86_64 aarch64; do
  dir=rpm/$arch/repodata
  fetch "$dir/repomd.xml" "$work/repomd.xml.$arch"
  fetch "$dir/repomd.xml.asc" "$work/repomd.xml.asc.$arch"
  if ! {
    [ "$(head -n 1 "$work/repomd.xml.asc.$arch")" = '-----BEGIN PGP SIGNATURE-----' ] &&
      [ "$(grep -c '^-----BEGIN PGP' "$work/repomd.xml.asc.$arch")" = 1 ]
  }; then
    die "repomd.xml.asc ($arch) is not a single signature"
  fi
  sig_ok "$work/key.gpg" "$primary" "$work/repomd.xml.asc.$arch" "$work/repomd.xml.$arch" ||
    die "repomd.xml ($arch) does not verify against the repository key"
  # The primary data: its sha256 and where it is, as createrepo_c writes them (one element per line).
  entry=$(awk '
    /<data type="primary">/ { inside = 1; next }
    /<\/data>/ { inside = 0 }
    inside && /<checksum type="sha256">/ { sub(/.*<checksum type="sha256">/, ""); sub(/<.*/, ""); h = h " " $0; n++ }
    inside && /<location href="/ { sub(/.*<location href="/, ""); sub(/".*/, ""); l = l " " $0; m++ }
    END { if (n == 1 && m == 1) print h l }' "$work/repomd.xml.$arch")
  # "<sha256> <location>": exactly one of each, and a plain file name under repodata/.
  case $entry in
    ' '*' repodata/'*) ;;
    *) die "repomd.xml ($arch) does not name primary.xml.gz once" ;;
  esac
  hash=${entry# }
  hash=${hash%% *}
  location=${entry##* }
  case $hash in *[!0-9a-f]* | '') hash=none ;; esac
  [ ${#hash} = 64 ] || die "repomd.xml ($arch) gives no sha256 for primary.xml.gz"
  case ${location#repodata/} in
    '' | *[!0-9A-Za-z._-]* | .*) die "repomd.xml ($arch) has an unexpected location for primary.xml.gz" ;;
  esac
  fetch "rpm/$arch/$location" "$work/primary.$arch.gz"
  [ "$(sha256sum < "$work/primary.$arch.gz" | cut -d' ' -f1)" = "$hash" ] ||
    die "primary.xml.gz ($arch) does not match the sha256 in repomd.xml"
  gzip -dc "$work/primary.$arch.gz" > "$work/primary.$arch.xml" || die "cannot decompress primary.xml.gz ($arch)"
  # "<ver>-<rel>" of every hodeishield package for this architecture.
  versions=$(awk -v a="$arch" '
    /<package type="rpm">/ { p = r = v = "" }
    /^ *<name>/ { p = $0; sub(/^ *<name>/, "", p); sub(/<.*/, "", p) }
    /^ *<arch>/ { r = $0; sub(/^ *<arch>/, "", r); sub(/<.*/, "", r) }
    /^ *<version / {
      v = $0; sub(/.* ver="/, "", v); sub(/".*/, "", v)
      rel = $0; sub(/.* rel="/, "", rel); sub(/".*/, "", rel)
      v = v "-" rel
    }
    /<\/package>/ { if (p == "hodeishield" && r == a && v != "") print v }' "$work/primary.$arch.xml")
  # The package is built with release 1.
  judge "DNF ($arch)" "$versions" "$expected-1"
done

# --- Key expiry -------------------------------------------------------------------------------------
# A renewal takes a release (see CONTRIBUTING.md), so the key is reported 60 days ahead. The expiry of
# the primary key and the latest expiry of its usable signing subkeys, as gpg lists them (field 7 is
# empty when the key never expires; field 2 is r for revoked and e for expired).
now=$(date +%s)
expiries=$(gpg --batch --with-colons --show-keys "$key" | awk -F: -v now="$now" '
  $1 == "pub" { prim = ($7 == "" ? "never" : $7) }
  $1 == "sub" && $2 !~ /[re]/ && $12 ~ /s/ {
    if ($7 == "") sub_never = 1
    else if ($7 > sub_max) sub_max = $7
    sub_seen = 1
  }
  END { if (prim == "" || !sub_seen) exit 1; print prim, (sub_never ? "never" : sub_max) }') ||
  die "cannot read the expiry of the public key $key"
soon=$((now + 60 * 86400))
for expiry in $expiries; do
  case $expiry in
    never) ;;
    *[!0-9]* | '') die "cannot read the expiry of the public key $key" ;;
    *)
      if [ "$expiry" -le "$soon" ]; then
        printf 'The repository key (or its signing subkey) expires on %s, within 60 days: renew it (CONTRIBUTING.md).\n' \
          "$(date -u -d "@$expiry" +%Y-%m-%d)"
        [ "$status" != 0 ] || status=5
      fi
      ;;
  esac
done

exit "$status"
