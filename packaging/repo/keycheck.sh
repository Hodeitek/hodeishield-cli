#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
#
# Fails unless the file holds exactly one OpenPGP primary key and its fingerprint is the pinned one.
#
#   keycheck.sh <public-key> [<readme>]
#
# The fingerprint is pinned here, apart from the README that users read and from packaging/gpg.key, so
# that changing the committed key (or the README) alone cannot go unnoticed: all three must agree. With
# <readme>, the README must also state the fingerprint (in groups of four, as it prints it) and the
# fingerprint without spaces used by its key check.
#
# The workflows call it before anything is uploaded; renewing the key keeps the fingerprint, so this
# constant changes only if the repository key itself is replaced.

set -eu

PINNED_FINGERPRINT=AA2AF21285A9AB990833908935D5F94171C1CD0B

die() {
  printf 'keycheck.sh: %s\n' "$*" >&2
  exit 1
}

key=$1
[ -s "$key" ] || die "the public key $key is missing or empty"
home=$(mktemp -d)
trap 'rm -rf "$home"' EXIT
primaries=$(GNUPGHOME=$home gpg --batch --with-colons --show-keys "$key" 2> /dev/null |
  awk -F: '$1 == "pub" { want = 1; next } $1 == "fpr" && want { print $10; want = 0 }')
if [ -z "$primaries" ] || [ "$(printf '%s\n' "$primaries" | wc -l)" -ne 1 ]; then
  die "$key does not hold exactly one primary key"
fi
[ "$primaries" = "$PINNED_FINGERPRINT" ] ||
  die "the primary key of $key is $primaries, not the pinned $PINNED_FINGERPRINT"

if [ $# -ge 2 ]; then
  readme=$2
  spaced=$(printf '%s' "$PINNED_FINGERPRINT" | sed 's/..../& /g; s/ $//; s/\(.\{24\}\) /\1  /')
  grep -Fqx "$spaced" "$readme" || die "$readme does not state the fingerprint as $spaced"
  grep -Fq "= $PINNED_FINGERPRINT ]" "$readme" || die "$readme does not check the fingerprint $PINNED_FINGERPRINT"
fi
printf 'keycheck.sh: %s holds exactly one key, %s\n' "$key" "$PINNED_FINGERPRINT"
