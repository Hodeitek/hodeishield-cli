#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
#
# Exports the repository's public key without its revoked signing subkeys, minimal (only the latest
# self-signatures), as ASCII armor on the standard output:
#
#   GNUPGHOME=<keyring> sh export-public-key.sh <primary-fingerprint> > gpg.key
#
# rpm on RHEL and Rocky Linux 8 and 9 refuses to import a public key that carries a revoked subkey, so
# the key published as /gpg.key and committed as packaging/gpg.key must not. The keyring only needs the
# public part of the primary key, the new signing subkey and the revocation of the old one. The output
# is checked before it is printed: exactly one primary key, no revoked subkey, and exactly one signing
# subkey that is neither revoked nor expired (and, when SIGNING_KEY is set, that is the one it names).

set -eu

primary=${1:?usage: export-public-key.sh <primary-fingerprint>}
: "${GNUPGHOME:?}"
case $primary in
  *[!0-9A-Fa-f]* | '') fail=1 ;;
  *) [ ${#primary} = 40 ] || fail=1 ;;
esac
[ -z "${fail-}" ] || {
  printf 'export-public-key.sh: the argument must be a 40-digit primary key fingerprint\n' >&2
  exit 2
}
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=/dev/null
. "$here/sigcheck.sh"

# The fingerprints of the revoked subkeys in the keyring: a "sub" record with validity "r", and the
# "fpr" record that follows it.
revoked=$(gpg --batch --with-colons --list-keys "$primary" |
  awk -F: '$1 == "pub" { want = 0 } $1 == "sub" { want = ($2 == "r") } $1 == "fpr" && want { print $10; want = 0 }')

filter=
for fpr in $revoked; do
  filter="${filter:+$filter || }fpr = $fpr"
done

out=$(mktemp)
trap 'rm -f "$out"' EXIT
if [ -n "$filter" ]; then
  gpg --batch --export-options export-minimal --export-filter "drop-subkey=$filter" \
    --armor --export "$primary" > "$out"
else
  gpg --batch --export-options export-minimal --armor --export "$primary" > "$out"
fi
[ -s "$out" ] || {
  printf 'export-public-key.sh: nothing exported for %s\n' "$primary" >&2
  exit 1
}

# What is about to be published: one primary key, no revoked subkey, and one signing subkey that is
# neither revoked nor expired.
[ "$(gpg --batch --with-colons --show-keys "$out" | grep -c '^pub:')" = 1 ] || {
  printf 'export-public-key.sh: the export does not hold exactly one primary key\n' >&2
  exit 1
}
problem=$(public_key_problem "$out" "${SIGNING_KEY-}")
if [ -n "$problem" ]; then
  printf 'export-public-key.sh: the export %s\n' "$problem" >&2
  exit 1
fi
cat "$out"
