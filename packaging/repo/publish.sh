#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
#
# Publishes a release's packages into the APT and DNF repositories kept in an S3-compatible bucket:
# downloads the packages already there and the signed index that vouches for them, runs build.sh over
# them and the new ones, then uploads the result so that no client can see an index that points at a
# file that is not there yet.
#
#   publish.sh <new-packages-dir>
#
# Environment (plus what build.sh needs: GNUPGHOME, SIGNING_KEY, PUBLIC_KEY):
#   PACKAGES_S3_ENDPOINT, PACKAGES_S3_REGION, PACKAGES_S3_BUCKET
#   PACKAGES_S3_ACCESS_KEY_ID, PACKAGES_S3_SECRET_ACCESS_KEY
#
# Runs in the pinned image named in packaging/repo/image. The bucket user may list, read and write
# but not delete, so nothing here removes anything: a published package is never replaced, and the
# files of older metadata that a new build leaves behind (by-hash indexes, hashed repodata) stay where
# they are, which is what lets a client with an older index finish its update.
#
# The bucket is served through a CDN that caches every object on its own, and uploads are not atomic,
# so Cache-Control is set by what a file is:
#   packages, by-hash indexes, hashed repodata   public, max-age=31536000, immutable
#       the name is the content (or the version): it never changes
#   InRelease, Release, Release.gpg, repomd.xml, repomd.xml.asc   no-cache
#       the entry points, which must never be served stale or out of step with each other
#   everything else (Packages*, per-architecture Release, .repo, gpg.key, index.html)
#       public, max-age=60

set -eu

new=$1
: "${PACKAGES_S3_ENDPOINT:?}" "${PACKAGES_S3_REGION:?}" "${PACKAGES_S3_BUCKET:?}"
: "${PACKAGES_S3_ACCESS_KEY_ID:?}" "${PACKAGES_S3_SECRET_ACCESS_KEY:?}"
here=$(cd "$(dirname "$0")" && pwd)

# rclone is configured from the environment only: no config file, and the bucket is never created.
export RCLONE_CONFIG=/dev/null
export RCLONE_CONFIG_PKG_TYPE=s3
export RCLONE_CONFIG_PKG_PROVIDER=Other
export RCLONE_CONFIG_PKG_ENDPOINT="$PACKAGES_S3_ENDPOINT"
export RCLONE_CONFIG_PKG_REGION="$PACKAGES_S3_REGION"
export RCLONE_CONFIG_PKG_ACCESS_KEY_ID="$PACKAGES_S3_ACCESS_KEY_ID"
export RCLONE_CONFIG_PKG_SECRET_ACCESS_KEY="$PACKAGES_S3_SECRET_ACCESS_KEY"
export RCLONE_S3_NO_CHECK_BUCKET=true
bucket=pkg:$PACKAGES_S3_BUCKET

forever='Cache-Control: public, max-age=31536000, immutable'
short='Cache-Control: public, max-age=60'
nocache='Cache-Control: no-cache'

repo=$(mktemp -d)
published=$(mktemp -d)
trap 'rm -rf "$repo" "$published"' EXIT

# The packages already published, which the indexes are regenerated from. Everything in the pool is
# downloaded, so that build.sh sees (and refuses) anything that the signed index does not vouch for.
rclone copy "$bucket" "$repo" --include '/apt/pool/**' --include '/rpm/*/*.rpm'

# The signed APT index as published (none before the first release), and the Packages files it lists,
# by hash: what build.sh checks the downloaded packages against. The hashes are read here before the
# signature is checked, only to know what to download; build.sh checks both.
rclone copy "$bucket" "$published" --include /apt/dists/stable/InRelease
if [ -e "$published/apt/dists/stable/InRelease" ]; then
  for arch in amd64 arm64; do
    hash=$(awk -v f="main/binary-$arch/Packages" \
      '/^[^ ]/ { s = ($0 == "SHA256:"); next } s && $3 == f { print $1 }' "$published/apt/dists/stable/InRelease")
    case $hash in *[!0-9a-f]* | '') hash=missing ;; esac
    [ ${#hash} = 64 ] || {
      printf 'publish.sh: the published InRelease does not give one SHA256 for Packages (%s)\n' "$arch" >&2
      exit 1
    }
    rclone copyto "$bucket/apt/dists/stable/main/binary-$arch/by-hash/SHA256/$hash" \
      "$published/apt/dists/stable/main/binary-$arch/Packages"
  done
fi

sh "$here/build.sh" "$repo" "$new" "$published/apt/dists/stable"

# Packages first. --immutable makes a published package that differs from the local copy an error.
rclone copy "$repo" "$bucket" --immutable --header-upload "$forever" \
  --include '/apt/pool/**' --include '/rpm/*/*.rpm'

# Then the indexes that are named by their hash: the by-hash copies of the APT indexes and the
# hashed repodata files of DNF (createrepo_c names them <sha256 of the file>-<type>.xml.gz, so a name
# never has other content). A file that is already there is skipped rather than checked with
# --immutable: it is rebuilt on every run, with a newer modification time, and would be reported as
# modified although it is identical.
rclone copy "$repo" "$bucket" --ignore-existing --header-upload "$forever" \
  --filter '- /rpm/*/repodata/repomd.xml' --filter '- /rpm/*/repodata/repomd.xml.asc' \
  --filter '+ /apt/dists/**/by-hash/**' --filter '+ /rpm/*/repodata/*' --filter '- **'

# Then every other file except the entry points of the indexes, uploaded again even when the size
# is unchanged.
rclone copy "$repo" "$bucket" --ignore-times --header-upload "$short" \
  --exclude '/apt/pool/**' --exclude '/rpm/*/*.rpm' \
  --exclude '/apt/dists/**/by-hash/**' --exclude '/rpm/*/repodata/*' \
  --exclude '/apt/dists/stable/InRelease' --exclude '/apt/dists/stable/Release' \
  --exclude '/apt/dists/stable/Release.gpg'

# The entry points last, one at a time, so an index is visible only after everything it lists.
for file in rpm/x86_64/repodata/repomd.xml rpm/x86_64/repodata/repomd.xml.asc \
  rpm/aarch64/repodata/repomd.xml rpm/aarch64/repodata/repomd.xml.asc \
  apt/dists/stable/Release apt/dists/stable/Release.gpg apt/dists/stable/InRelease; do
  rclone copyto "$repo/$file" "$bucket/$file" --ignore-times --header-upload "$nocache"
done
