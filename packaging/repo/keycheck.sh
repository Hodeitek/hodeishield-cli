#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
#
# Fails unless the file holds exactly one OpenPGP primary key, its fingerprint is the pinned one, and
# it carries exactly one signing subkey that is neither revoked, expired nor invalid, which is the
# pinned signing subkey.
#
#   keycheck.sh <public-key> [<readme>]
#
# The fingerprint is pinned here, apart from the README that users read and from packaging/gpg.key, so
# that changing the committed key (or the README) alone cannot go unnoticed: all three must agree. With
# <readme>, the README must also state both fingerprints (in groups of four, as gpg prints them) and
# the primary fingerprint without spaces used by its key check.
#
# The workflows call it before anything is uploaded. Renewing the key keeps both fingerprints, so
# PINNED_FINGERPRINT changes only if the repository key itself is replaced, and PINNED_SIGNING_SUBKEY
# only when the signing subkey is rotated (CONTRIBUTING.md, "The repository signing key"): that change
# goes with the new packaging/gpg.key and the README, in the same pull request.

set -eu

PINNED_FINGERPRINT=AA2AF21285A9AB990833908935D5F94171C1CD0B
PINNED_SIGNING_SUBKEY=DC7E2403287CDB08BD84AD7DD7E72E1B635666B0

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
# Signing-capable subkeys that are usable: not revoked, expired or invalid (field 2 r, e or i).
signers=$(GNUPGHOME=$home gpg --batch --with-colons --show-keys "$key" 2> /dev/null |
  awk -F: '$1 == "sub" { s = ($12 ~ /s/ && $2 !~ /[rei]/) } $1 == "fpr" && s { print $10; s = 0 }')
if [ -z "$signers" ] || [ "$(printf '%s\n' "$signers" | wc -l)" -ne 1 ]; then
  die "$key does not carry exactly one usable signing subkey"
fi
[ "$signers" = "$PINNED_SIGNING_SUBKEY" ] ||
  die "the signing subkey of $key is $signers, not the pinned $PINNED_SIGNING_SUBKEY"

if [ $# -ge 2 ]; then
  readme=$2
  spaced() { printf '%s' "$1" | sed 's/..../& /g; s/ $//; s/\(.\{24\}\) /\1  /'; }
  spaced=$(spaced "$PINNED_FINGERPRINT")
  grep -Fqx "$spaced" "$readme" || die "$readme does not state the fingerprint as $spaced"
  spaced=$(spaced "$PINNED_SIGNING_SUBKEY")
  grep -Fqx "$spaced" "$readme" || die "$readme does not state the signing subkey as $spaced"
  grep -Fq "= \"$PINNED_FINGERPRINT $PINNED_SIGNING_SUBKEY\" ]" "$readme" ||
    die "$readme does not check the fingerprint $PINNED_FINGERPRINT and the signing subkey $PINNED_SIGNING_SUBKEY"
fi
printf 'keycheck.sh: %s holds exactly one key, %s, signing subkey %s\n' "$key" "$PINNED_FINGERPRINT" \
  "$PINNED_SIGNING_SUBKEY"
