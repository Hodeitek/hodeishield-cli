#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
#
# Maintenance run, for after the signing subkey has been revoked and replaced: signs the RPM packages
# of the bucket again with the new subkey and regenerates every index. Not part of a release.
#
#   resign.sh [--apply] <release-rpms-dir> <release-debs-dir>
#
# Without --apply nothing is uploaded: the bucket is read, the repository is built and checked in a
# temporary directory, and a summary is printed. --apply uploads, and also needs RESIGN_CONFIRM set to
# the primary key fingerprint that the README publishes (spaces allowed).
#
# <release-rpms-dir> and <release-debs-dir> hold the .rpm and the .deb assets of every release in the
# bucket, as the releases publish them, each verified against the release's SHA256SUMS and that file's
# cosign signature (the maintenance workflow does that, and mounts them read-only). They are the only
# trusted source. Before any package or index is signed, every package in the bucket must be one of
# them: a .deb byte for byte, an .rpm with the same name, epoch, version, release and architecture, the
# same header and payload digests and the same bytes after its signature header (only the signature
# differs). The set of packages in the bucket must be exactly the set of assets, and any other file in
# the pool, or any other .rpm under rpm/, stops the run. The RPM packages are then signed again from the
# assets, never from the bucket's copies.
#
# Environment: the same as publish.sh (PACKAGES_S3_*, GNUPGHOME, SIGNING_KEY, PUBLIC_KEY). PUBLIC_KEY
# is the new public key, exported without the revoked subkey (export-public-key.sh). README_FILE is the
# repository's README.md, which publishes the fingerprint of the primary key that users check.
#
# It refuses to run when the primary key of PUBLIC_KEY is not the one the README publishes, when
# PUBLIC_KEY carries a revoked subkey, when it does not carry exactly one usable
# signing subkey (the one named by SIGNING_KEY), or when a signature made with SIGNING_KEY
# does not verify against PUBLIC_KEY (the same check build.sh applies; that test signature, over a
# fixed text, is the only one made before the bucket is checked, and is thrown away). The old signatures
# and the published InRelease, made by the revoked subkey, are not trusted and not read: the APT index is
# regenerated from the release assets alone. The RPM files are uploaded under their own names: the
# bucket's versioning keeps the previous objects, nothing is deleted. Runs in the pinned image named in
# packaging/repo/image.

set -eu

usage() {
  sed -n '/^#   resign.sh/,/^# Environment:/p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit "${1:-2}"
}

apply=
case ${1-} in
  -h | --help) usage 0 ;;
  --apply)
    apply=1
    shift
    ;;
esac
[ $# = 2 ] || usage 2
rpms=$1
debs=$2

die() {
  printf 'resign.sh: %s\n' "$*" >&2
  exit 1
}

: "${GNUPGHOME:?}" "${SIGNING_KEY:?}" "${PUBLIC_KEY:?}" "${README_FILE:?}"
: "${PACKAGES_S3_ENDPOINT:?}" "${PACKAGES_S3_REGION:?}" "${PACKAGES_S3_BUCKET:?}"
: "${PACKAGES_S3_ACCESS_KEY_ID:?}" "${PACKAGES_S3_SECRET_ACCESS_KEY:?}"
here=$(cd "$(dirname "$0")" && pwd)
[ -d "$rpms" ] || die "$rpms is not a directory"
[ -d "$debs" ] || die "$debs is not a directory"
[ -s "$PUBLIC_KEY" ] || die "$PUBLIC_KEY is missing or empty"
# Only regular files, .rpm in one directory and .deb in the other; build.sh checks their names.
odd=$(find "$rpms" -mindepth 1 \( ! -type f -o ! -name '*.rpm' \) -print)
[ -z "$odd" ] || die "$rpms holds something other than .rpm files: $odd"
odd=$(find "$debs" -mindepth 1 \( ! -type f -o ! -name '*.deb' \) -print)
[ -z "$odd" ] || die "$debs holds something other than .deb files: $odd"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
primary=$(gpg --batch --with-colons --show-keys "$PUBLIC_KEY" | awk -F: '$1 == "fpr" { print $10; exit }')
[ -n "$primary" ] || die "cannot read the fingerprint of $PUBLIC_KEY"

# The primary key is the one users check against the README: the first line after "The repositories
# are signed with this key" that is, without its spaces, 40 hexadecimal digits.
published=$(awk '/^The repositories are signed with this key/ { on = 1; next }
  on && /^#/ { exit }
  on { gsub(/[ \t]/, ""); if (length($0) == 40 && $0 !~ /[^0-9A-F]/) { print; exit } }' "$README_FILE")
[ -n "$published" ] || die "cannot read the primary key fingerprint that $README_FILE publishes"
[ "$primary" = "$published" ] ||
  die "the primary key of $PUBLIC_KEY is $primary, not the one the README publishes ($published)"

# The key to publish must be one that rpm on RHEL and Rocky Linux 8 and 9 can import (no revoked
# subkey), and must carry exactly one usable signing subkey: the one that signs, SIGNING_KEY.
# shellcheck source=/dev/null
. "$here/sigcheck.sh"
problem=$(public_key_problem "$PUBLIC_KEY" "$SIGNING_KEY")
[ -z "$problem" ] || die "$PUBLIC_KEY $problem"

# A signature made with the new subkey must verify against the public key, as build.sh will require.
# Defence in depth, which no test reaches: public_key_problem above already requires SIGNING_KEY to be
# the one usable signing subkey of PUBLIC_KEY, so this fails only if the keyring's secret for that
# fingerprint does not match the published subkey, which repo-test.sh cannot construct.
gpg --batch --quiet --dearmor --output "$tmp/key.gpg" "$PUBLIC_KEY"
printf 'resign.sh preflight\n' > "$tmp/probe"
gpg --batch --yes --local-user "$SIGNING_KEY" --digest-algo SHA512 --armor --detach-sign \
  --output "$tmp/probe.asc" "$tmp/probe" 2> /dev/null ||
  die "cannot sign with $SIGNING_KEY"
sig_ok "$tmp/key.gpg" "$primary" "$tmp/probe.asc" "$tmp/probe" ||
  die "a signature made with $SIGNING_KEY does not verify against $PUBLIC_KEY; nothing was read or changed"

if [ -n "$apply" ]; then
  confirm=$(printf '%s' "${RESIGN_CONFIRM-}" | tr -d ' ' | tr a-f A-F)
  if [ -z "$confirm" ] || [ "$confirm" != "$primary" ]; then
    die "--apply needs RESIGN_CONFIRM set to the primary key fingerprint published in the README ($primary)"
  fi
  dry=
  printf 'resign.sh: APPLY, key %s: the bucket will be changed\n' "$primary"
else
  dry=1
  printf 'resign.sh: dry run, key %s: the bucket is only read\n' "$primary"
fi

# The assets as publish.sh and build.sh take them: one directory, read from here on only.
mkdir "$tmp/assets"
find "$rpms" "$debs" -mindepth 1 -maxdepth 1 -type f -exec cp -t "$tmp/assets/" {} +

status=0
RESIGN=1 DRY_RUN=$dry sh "$here/publish.sh" "$tmp/assets" || status=$?
[ "$status" = 0 ] || die "failed (exit $status); see above"
if [ -n "$apply" ]; then
  printf 'resign.sh: done. Purge the CDN cache for /rpm/*/*.rpm and the entry points (CONTRIBUTING.md).\n'
else
  printf 'resign.sh: dry run complete, nothing was uploaded. Run again with --apply to publish.\n'
fi
