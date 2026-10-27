#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
#
# Reads which releases the bucket holds packages of, for the re-sign workflow (package-resign.yml), and
# prints their versions, one per line, sorted:
#
#   bucket-releases.sh <stable-releases> <listing.json>...
#
# <stable-releases> lists the repository's published stable releases, one version per line (0.5.2, no
# leading "v"). Each <listing.json> is the output of `aws s3api list-objects-v2 --output json` for a
# prefix of the bucket (apt/pool/ and rpm/). Needs jq.
#
# The bucket is not trusted: an object name only selects a release, and the workflow then verifies that
# release's packages, which resign.sh requires the bucket to hold exactly. It fails, printing why, when:
#   - an object name holds anything but letters, digits and . _ / + ~ - (a newline, for one);
#   - an object under apt/pool/, or an .rpm under rpm/, is not named as build.sh names a package;
#   - the bucket holds no package;
#   - a release has not exactly its four packages (two .deb, two .rpm) in the bucket;
#   - a release in the bucket is not a published stable release;
#   - a published stable release newer than LAST_RELEASE_WITHOUT_REPOSITORY (packaging/repo/live.sh)
#     has no package in the bucket. Older ones predate the repositories and are left out.
# Other objects under rpm/ (the indexes) are rebuilt by the run and not looked at here.

set -eu

die() {
  printf 'bucket-releases.sh: %s\n' "$*" >&2
  exit 1
}

[ $# -ge 2 ] || die "usage: bucket-releases.sh <stable-releases> <listing.json>..."
stable=$1
shift
here=$(cd "$(dirname "$0")" && pwd)
last=$(sed -n 's/^LAST_RELEASE_WITHOUT_REPOSITORY=//p' "$here/live.sh")
case $last in
  *[!0-9.]* | '' | .* | *.) die "cannot read LAST_RELEASE_WITHOUT_REPOSITORY from live.sh" ;;
esac
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Every name as a JSON string, one per line: a name holding a newline or any other control character
# stays on its line, escaped, and is refused below.
for listing in "$@"; do
  jq -r '(.Contents // [])[] | .Key | @json' "$listing" || die "$listing is not a bucket listing"
done > "$tmp/names"

: > "$tmp/found"
while IFS= read -r quoted; do
  case $quoted in
    \"*\") name=${quoted#\"} name=${name%\"} ;;
    *) die "unexpected listing line: $quoted" ;;
  esac
  case $name in
    '' | *[!A-Za-z0-9._/+~-]*) die "an object name holds an unexpected character: $quoted" ;;
  esac
  v=$(printf '%s\n' "$name" | sed -n -E \
    -e 's#^apt/pool/main/h/hodeishield/hodeishield_([0-9]+\.[0-9]+\.[0-9]+)-1_(amd64|arm64)\.deb$#\1#p' \
    -e 's#^rpm/x86_64/hodeishield-([0-9]+\.[0-9]+\.[0-9]+)-1\.x86_64\.rpm$#\1#p' \
    -e 's#^rpm/aarch64/hodeishield-([0-9]+\.[0-9]+\.[0-9]+)-1\.aarch64\.rpm$#\1#p')
  if [ -n "$v" ]; then
    printf '%s\n' "$v" >> "$tmp/found"
    continue
  fi
  case $name in
    apt/pool/* | rpm/*.rpm) die "unexpected package object in the bucket: $name" ;;
  esac
done < "$tmp/names"

[ -s "$tmp/found" ] || die "the bucket holds no package; there is nothing to sign again"
LC_ALL=C sort -V -u "$tmp/found" > "$tmp/versions"
while IFS= read -r v; do
  n=$(grep -cFx "$v" "$tmp/found")
  [ "$n" = 4 ] || die "release $v has $n packages in the bucket, not its 4"
done < "$tmp/versions"

grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' "$stable" | LC_ALL=C sort -V -u > "$tmp/stable"
notstable=$(grep -vxF -f "$tmp/stable" "$tmp/versions" | tr '\n' ' ')
[ -z "$notstable" ] || die "packages of releases that are not published stable releases are in the bucket: $notstable"
: > "$tmp/missing"
while IFS= read -r v; do
  grep -qFx "$v" "$tmp/versions" && continue
  # At or below the last release without the repositories: never published there.
  [ "$(printf '%s\n%s\n' "$v" "$last" | LC_ALL=C sort -V | tail -n 1)" = "$last" ] && continue
  printf '%s ' "$v" >> "$tmp/missing"
done < "$tmp/stable"
[ ! -s "$tmp/missing" ] ||
  die "published stable releases newer than $last have no package in the bucket: $(cat "$tmp/missing")(a release whose repos job has not run yet must be published first)"

cat "$tmp/versions"
