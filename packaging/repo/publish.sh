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
#
# With RESIGN=1 (set by resign.sh, never by a release) it does the one-off recovery after a signing
# subkey revocation instead: <new-packages-dir> holds the verified release assets of every package in
# the bucket, the RPM packages are signed again from them and uploaded over the old ones (the bucket's
# versioning keeps those), and the indexes are rebuilt without reading the published InRelease. Every
# package in the bucket must be one of those assets, checked before anything is signed. DRY_RUN=1
# stops before anything is uploaded. The re-signed RPM files get max-age=60 where a new package is immutable,
# deliberately: they replace objects that caches may hold as immutable under the same URL, and a short
# lifetime lets the CDN purge and the clients' own caches converge instead of pinning the replacement.

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
# Every download names the local encoding explicitly (rclone's default for local files): an object
# named "." or "..", or holding a "/" of its own, is stored under an escaped name, never as a path
# outside the directory it is downloaded to.
fetch() { rclone "$@" --local-encoding Slash,Dot; }

forever='Cache-Control: public, max-age=31536000, immutable'
short='Cache-Control: public, max-age=60'
nocache='Cache-Control: no-cache'

repo=$(mktemp -d)
published=$(mktemp -d)
trap 'rm -rf "$repo" "$published"' EXIT

# The packages already published, which the indexes are regenerated from. Everything in the pool is
# downloaded, so that build.sh sees (and refuses) anything that the signed index does not vouch for.
fetch copy "$bucket" "$repo" --include '/apt/pool/**' --include '/rpm/*/*.rpm'

resign=${RESIGN:-}
if [ -n "$resign" ]; then
  # Every check of the recovery runs here, before build.sh, and so before any package or index is
  # signed. Only the verified release assets in <new-packages-dir> are trusted: each package in the
  # bucket must be one of them, a .deb byte for byte and an .rpm apart from its signature header, and
  # the bucket and the assets must hold the same set of packages. The old signatures are not looked
  # at, and build.sh signs the RPM packages again from the release assets, never from the bucket's
  # copies. The working files and the rpm database live in $aux, apart from the bucket's files.
  aux=$(mktemp -d)
  back=$(mktemp -d)
  trap 'rm -rf "$repo" "$published" "$aux" "$back"' EXIT
  die() {
    printf 'publish.sh: %s\n' "$*" >&2
    exit 1
  }
  # Only regular files with the names that build.sh writes, where it writes them, reach rpm.
  odd=$(cd "$repo" && find . -regextype posix-extended ! -type d ! \( -type f \( \
    -regex '\./apt/pool/main/h/hodeishield/hodeishield_[0-9A-Za-z.+~-]+_(amd64|arm64)\.deb' -o \
    -regex '\./rpm/x86_64/hodeishield-[0-9A-Za-z.+~^_-]+\.x86_64\.rpm' -o \
    -regex '\./rpm/aarch64/hodeishield-[0-9A-Za-z.+~^_-]+\.aarch64\.rpm' \) \) -print)
  [ -z "$odd" ] || die "unexpected files in the bucket: $odd"
  (cd "$repo" && find . -type f \( -name '*.deb' -o -name '*.rpm' \) -exec basename {} \;) | sort > "$aux/bucket"
  (cd "$new" && find . -type f -exec basename {} \;) | sort > "$aux/verified"
  [ -s "$aux/bucket" ] || die "the bucket holds no package; there is nothing to sign again"
  comm -3 "$aux/bucket" "$aux/verified" > "$aux/differ"
  [ ! -s "$aux/differ" ] || {
    cat "$aux/differ" >&2
    die "the packages in the bucket (left) and the release assets (right, indented) differ; nothing is signed"
  }
  for deb in "$repo"/apt/pool/main/h/hodeishield/*.deb; do
    [ -e "$deb" ] || continue
    cmp -s "$new/$(basename "$deb")" "$deb" ||
      die "${deb#"$repo"/} in the bucket differs from its release asset; nothing is signed"
  done
  mkdir "$aux/db"
  nevra() {
    rpm --dbpath "$aux/db" -qp --qf '%{NAME} %{EPOCHNUM} %{VERSION} %{RELEASE} %{ARCH}' "$1" 2> /dev/null
  }
  # be32 <file> <offset>: the 32-bit big-endian number at that offset.
  be32() {
    od -An -v -tu1 -j "$2" -N 4 "$1" |
      awk '{ for (i = 1; i <= NF; i++) { n = n * 256 + $i; c++ } } END { if (c == 4) print n }'
  }
  # body <rpm>: the SHA256 of everything after the signature header, the main header and the payload,
  # which signing leaves byte for byte as they are. The signature header follows the 96-byte lead, has
  # a 16-byte intro (magic, then the number of index entries and the length of the data, which give
  # its size) and is padded to a multiple of 8 bytes.
  body() {
    [ "$(od -An -v -tx1 -N 4 "$1" | tr -d ' \n')" = edabeedb ] || return 1
    [ "$(od -An -v -tx1 -j 96 -N 8 "$1" | tr -d ' \n')" = 8eade80100000000 ] || return 1
    entries=$(be32 "$1" 104)
    length=$(be32 "$1" 108)
    [ -n "$entries" ] && [ -n "$length" ] || return 1
    tail -c "+$((96 + (16 + 16 * entries + length + 7) / 8 * 8 + 1))" "$1" | sha256sum | cut -d' ' -f1
  }
  # What signing does not change: the digest of the main header, the payload digest that the main
  # header records, and the bytes of the main header and the payload. rpm checks the header digest
  # against the main header when it reads a package; the bytes after the signature header are compared
  # as well, as defence in depth.
  identity() {
    rpm --dbpath "$aux/db" -qp --qf '%{SHA256HEADER} [%{PAYLOADDIGEST} ]' "$1" 2> /dev/null || return 1
    body "$1"
  }
  : > "$aux/old.sums"
  for rpm in "$repo"/rpm/*/*.rpm; do
    [ -e "$rpm" ] || continue
    path=${rpm#"$repo"/}
    asset=$new/$(basename "$rpm")
    mine=$(nevra "$rpm") && [ -n "$mine" ] || die "cannot read $path in the bucket; nothing is signed"
    [ "$(nevra "$asset")" = "$mine" ] ||
      die "$path in the bucket is not the same package as its release asset; nothing is signed"
    want=$(identity "$asset") || die "cannot read the release asset of $path"
    got=$(identity "$rpm") || die "cannot read $path in the bucket; nothing is signed"
    [ "$got" = "$want" ] ||
      die "$path in the bucket differs from its release asset beyond the signature; nothing is signed"
    (cd "$repo" && sha256sum "$path") >> "$aux/old.sums"
  done
  # Only the local copy: build.sh signs them again from the release assets.
  rm -f "$repo"/rpm/*/*.rpm
fi

# The signed APT index as published (none before the first release), and the Packages files it lists,
# by hash: what build.sh checks the downloaded packages against. The hashes are read here before the
# signature is checked, only to know what to download; build.sh checks both.
# (Not in a recovery: that InRelease was signed by the revoked subkey and is not trusted.)
[ -n "$resign" ] || fetch copy "$bucket" "$published" --include /apt/dists/stable/InRelease
if [ -e "$published/apt/dists/stable/InRelease" ]; then
  for arch in amd64 arm64; do
    hash=$(awk -v f="main/binary-$arch/Packages" \
      '/^[^ ]/ { s = ($0 == "SHA256:"); next } s && $3 == f { print $1 }' "$published/apt/dists/stable/InRelease")
    case $hash in *[!0-9a-f]* | '') hash=missing ;; esac
    [ ${#hash} = 64 ] || {
      printf 'publish.sh: the published InRelease does not give one SHA256 for Packages (%s)\n' "$arch" >&2
      exit 1
    }
    fetch copyto "$bucket/apt/dists/stable/main/binary-$arch/by-hash/SHA256/$hash" \
      "$published/apt/dists/stable/main/binary-$arch/Packages"
  done
fi

sh "$here/build.sh" "$repo" "$new" "$published/apt/dists/stable"

if [ -n "$resign" ]; then
  printf 'RPM packages signed again (build.sh verified each one against the new key):\n'
  (cd "$repo" && sha256sum rpm/*/*.rpm) | while read -r sum file; do
    printf '  %s\n    before %s\n    after  %s\n' "$file" \
      "$(awk -v f="$file" '$2 == f { print $1 }' "$aux/old.sums")" "$sum"
  done
  if [ -n "${DRY_RUN:-}" ]; then
    printf 'Dry run: nothing was uploaded.\n'
    exit 0
  fi
fi

# Packages first. --immutable makes a published package that differs from the local copy an error;
# in a recovery that holds for the .deb files, and the re-signed .rpm files go over the old ones.
if [ -n "$resign" ]; then
  rclone copy "$repo" "$bucket" --immutable --header-upload "$forever" --include '/apt/pool/**'
  rclone copy "$repo" "$bucket" --ignore-times --header-upload "$short" --include '/rpm/*/*.rpm'
else
  rclone copy "$repo" "$bucket" --immutable --header-upload "$forever" \
    --include '/apt/pool/**' --include '/rpm/*/*.rpm'
fi

# A recovery reads the RPM packages back from the bucket before any index is uploaded: they must be
# the re-signed files, and a failure leaves the published indexes as they were.
if [ -n "$resign" ]; then
  fetch copy "$bucket" "$back" --include '/rpm/*/*.rpm'
  for rpm in "$repo"/rpm/*/*.rpm; do
    cmp -s "$rpm" "$back/${rpm#"$repo"/}" ||
      die "${rpm#"$repo"/} in the bucket is not the re-signed file"
  done
  printf 'Re-signed RPM packages uploaded and read back from the bucket.\n'
fi

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
