#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
#
# Decides whether the freshness monitor has anything to check: it is inert only while the domain
# serves no APT or DNF index at all. Once an index is served, the repository key must be present, so
# deleting packaging/gpg.key can never turn the monitor green.
#
#   live.sh <base-url> <public-key>
#
# <base-url> is the root of the repositories (https://packages.hodeishield.com) and <public-key> the
# path of packaging/gpg.key. The entry points are the ones freshness.sh reads: apt/dists/stable/InRelease
# and rpm/<arch>/repodata/repomd.xml for x86_64 and aarch64.
#
# Environment:
#   FRESHNESS_ALLOW_HTTP  1 allows a plain http base URL, which is only for testing against a local server
#   FRESHNESS_RETRIES     retries of a failed request (default 3)
#   FRESHNESS_LATEST_RELEASE      version of the latest stable release (0.5.2, no leading "v"); required
#   FRESHNESS_RELEASE_AGE_HOURS   hours since that release was published; required
#   FRESHNESS_GRACE_HOURS         hours a new release may take to appear (default 48)
#
# Time bound: no retry starts once 40 s have passed since the first attempt of a request, and an attempt
# lasts at most 20 s, so a request takes at most 60 s and the three of them 180 s.
#
# "Not live" is acceptable only before the first release that publishes the repositories. Every release up
# to LAST_RELEASE_WITHOUT_REPOSITORY (below) predates them. A clean 404 with a newer latest release is
# accepted only during the grace period after that release was published, and is a failure afterwards.
#
# Exit status: 0 when an index is served and the key is present and readable (run freshness.sh);
# 10 when every entry point answers with a clean 404 and not being live is still acceptable (nothing to
# check); 1 for anything else, including a clean 404 that is no longer acceptable. Failing closed: only a plain HTTP 404 means "not there". A DNS or TLS failure, a timeout, a 403,
# a 5xx, a redirect or any other answer is a failure, and so is a served index without the key.

set -eu

base=$1
key=$2
retries=${FRESHNESS_RETRIES:-3}
# The last release published before the repositories existed. Raise it never: it is what makes a 404 a
# failure for every later release.
LAST_RELEASE_WITHOUT_REPOSITORY=0.5.1
latest=${FRESHNESS_LATEST_RELEASE:-}
age=${FRESHNESS_RELEASE_AGE_HOURS:-}
grace=${FRESHNESS_GRACE_HOURS:-48}

die() {
  printf 'live.sh: %s\n' "$*" >&2
  exit 1
}

case $retries in
  *[!0-9]* | '') die "FRESHNESS_RETRIES is not a number" ;;
esac
case $latest in
  *[!0-9.]* | '' | .* | *.) die "FRESHNESS_LATEST_RELEASE is not a version: $latest" ;;
esac
case $age in
  *[!0-9]* | '') die "FRESHNESS_RELEASE_AGE_HOURS is not a number" ;;
esac
case $grace in
  *[!0-9]* | '') die "FRESHNESS_GRACE_HOURS is not a number" ;;
esac
proto='=https'
if [ "${FRESHNESS_ALLOW_HTTP:-}" = 1 ]; then proto='=http,https'; fi
case $base in
  http://* | https://*) ;;
  *) die "the base URL is not an http(s) URL: $base" ;;
esac
base=${base%/}
stamp=$(date +%s)

served=0
missing=0
for path in apt/dists/stable/InRelease rpm/x86_64/repodata/repomd.xml rpm/aarch64/repodata/repomd.xml; do
  # No --fail: the status itself is the answer. Redirects are not followed, so one is not a 404.
  code=$(curl --silent --show-error --proto "$proto" --connect-timeout 10 --max-time 20 \
    --retry "$retries" --retry-delay 2 --retry-max-time 40 \
    --header 'Cache-Control: no-cache' --header 'Pragma: no-cache' \
    --output /dev/null --write-out '%{http_code}' "$base/$path?nocache=$stamp") ||
    die "cannot reach $base/$path"
  case $code in
    404) missing=$((missing + 1)) ;;
    200) served=$((served + 1)) ;;
    *) die "$base/$path answered HTTP $code, which is neither a served index nor a clean 404" ;;
  esac
done

if [ "$served" = 0 ]; then
  # Not live is fine before the first release that publishes the repositories, and shortly after it.
  if [ "$(printf '%s\n%s\n' "$latest" "$LAST_RELEASE_WITHOUT_REPOSITORY" | LC_ALL=C sort -V | tail -n 1)" != "$LAST_RELEASE_WITHOUT_REPOSITORY" ]; then
    if [ "$age" -ge "$grace" ]; then
      die "$base serves no APT or DNF index, but release $latest (published $age hours ago, grace $grace hours) is newer than $LAST_RELEASE_WITHOUT_REPOSITORY, the last one without the repositories"
    fi
    printf 'live.sh: release %s is only %s hours old (grace %s hours); %s serves no index yet.\n' \
      "$latest" "$age" "$grace" "$base"
    exit 10
  fi
  printf 'live.sh: %s serves no APT or DNF index yet (%s of 3 entry points answer 404); nothing to check.\n' \
    "$base" "$missing"
  exit 10
fi

printf 'live.sh: %s serves an index (%s of 3 entry points).\n' "$base" "$served"
if [ ! -f "$key" ] || [ ! -r "$key" ] || [ ! -s "$key" ]; then
  die "the repositories are live but the public key $key is missing, empty or unreadable"
fi
exit 0
