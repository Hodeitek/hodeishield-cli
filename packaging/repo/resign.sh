#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
#
# Maintenance run, for after the signing subkey has been revoked and replaced: signs the RPM packages
# of the bucket again with the new subkey and regenerates every index. Not part of a release.
#
#   resign.sh [--apply] <verified-packages-dir>
#
# Without --apply nothing is uploaded: the bucket is read, the repository is built and checked in a
# temporary directory, and a summary is printed. --apply uploads, and also needs RESIGN_CONFIRM set to
# the fingerprint of the primary key in PUBLIC_KEY.
#
# <verified-packages-dir> holds the packages of every release in the bucket, each verified against the
# release's SHA256SUMS (the maintenance workflow does that). It is the only trusted source: the bucket's
# .deb files must be identical to these, and each bucket .rpm must be the same package (same header
# digest), only with a signature. The RPM packages are then signed again from these files. The set of
# packages in the bucket must be exactly the set in this directory.
#
# Environment: the same as publish.sh (PACKAGES_S3_*, GNUPGHOME, SIGNING_KEY, PUBLIC_KEY). PUBLIC_KEY
# is the new public key, exported without the revoked subkey (export-public-key.sh).
#
# It refuses to run when PUBLIC_KEY carries a revoked subkey, when it does not carry exactly one usable
# signing subkey (the one named by SIGNING_KEY), or when a signature made with SIGNING_KEY
# does not verify against PUBLIC_KEY (the same check build.sh applies). The old signatures and the
# published InRelease, made by the revoked subkey, are not trusted and not read. The RPM files are
# uploaded under their own names: the bucket's versioning keeps the previous objects, nothing is
# deleted. Runs in the pinned image named in packaging/repo/image.

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
[ $# = 1 ] || usage 2
verified=$1

die() {
  printf 'resign.sh: %s\n' "$*" >&2
  exit 1
}

: "${GNUPGHOME:?}" "${SIGNING_KEY:?}" "${PUBLIC_KEY:?}"
: "${PACKAGES_S3_ENDPOINT:?}" "${PACKAGES_S3_REGION:?}" "${PACKAGES_S3_BUCKET:?}"
: "${PACKAGES_S3_ACCESS_KEY_ID:?}" "${PACKAGES_S3_SECRET_ACCESS_KEY:?}"
here=$(cd "$(dirname "$0")" && pwd)
[ -d "$verified" ] || die "$verified is not a directory"
[ -s "$PUBLIC_KEY" ] || die "$PUBLIC_KEY is missing or empty"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
primary=$(gpg --batch --with-colons --show-keys "$PUBLIC_KEY" | awk -F: '$1 == "fpr" { print $10; exit }')
[ -n "$primary" ] || die "cannot read the fingerprint of $PUBLIC_KEY"

# The key to publish must be one that rpm on RHEL and Rocky Linux 8 and 9 can import (no revoked
# subkey), and must carry exactly one usable signing subkey: the one that signs, SIGNING_KEY.
# shellcheck source=/dev/null
. "$here/sigcheck.sh"
problem=$(public_key_problem "$PUBLIC_KEY" "$SIGNING_KEY")
[ -z "$problem" ] || die "$PUBLIC_KEY $problem"

# A signature made with the new subkey must verify against the public key, as build.sh will require.
gpg --batch --quiet --dearmor --output "$tmp/key.gpg" "$PUBLIC_KEY"
printf 'resign.sh preflight\n' > "$tmp/probe"
gpg --batch --yes --local-user "$SIGNING_KEY" --digest-algo SHA512 --armor --detach-sign \
  --output "$tmp/probe.asc" "$tmp/probe" 2> /dev/null ||
  die "cannot sign with $SIGNING_KEY"
sig_ok "$tmp/key.gpg" "$primary" "$tmp/probe.asc" "$tmp/probe" ||
  die "a signature made with $SIGNING_KEY does not verify against $PUBLIC_KEY; nothing was read or changed"

if [ -n "$apply" ]; then
  [ -n "${RESIGN_CONFIRM-}" ] && [ "$RESIGN_CONFIRM" = "$primary" ] ||
    die "--apply needs RESIGN_CONFIRM set to the primary key fingerprint $primary"
  dry=
  printf 'resign.sh: APPLY, key %s: the bucket will be changed\n' "$primary"
else
  dry=1
  printf 'resign.sh: dry run, key %s: the bucket is only read\n' "$primary"
fi

status=0
RESIGN=1 DRY_RUN=$dry sh "$here/publish.sh" "$verified" || status=$?
[ "$status" = 0 ] || die "failed (exit $status); see above"
if [ -n "$apply" ]; then
  printf 'resign.sh: done. Purge the CDN cache for /rpm/*/*.rpm and the entry points (CONTRIBUTING.md).\n'
else
  printf 'resign.sh: dry run complete, nothing was uploaded. Run again with --apply to publish.\n'
fi
