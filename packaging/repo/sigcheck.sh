# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
#
# Sourced by build.sh, freshness.sh, resign.sh and export-public-key.sh, not run on its own.
#
# gpgv exits 0 for a signature made by an expired or a revoked key, and for an expired signature: it
# reports those on the status fd only (EXPKEYSIG, REVKEYSIG, EXPSIG). So the exit status is not
# believed; the status lines are.
#
#   sig_ok <keyring> <primary-fingerprint> <gpgv arguments>
#
# Succeeds only when gpgv exits 0, reports a GOODSIG and a VALIDSIG made by the key whose primary key
# has that fingerprint (a signing subkey reports its primary key there), and reports none of EXPKEYSIG,
# REVKEYSIG, EXPSIG, BADSIG or ERRSIG. Anything else, including no status at all, fails. The arguments
# are those of gpgv after the keyring: [--output <file>] <signature> [<signed file>].
sig_ok() {
  sig_keyring=$1
  sig_primary=$2
  shift 2
  sig_status=$(gpgv --keyring "$sig_keyring" --status-fd 1 "$@" 2> /dev/null) || return 1
  printf '%s\n' "$sig_status" | awk -v primary="$sig_primary" '
    $1 != "[GNUPG:]" { next }
    $2 == "EXPKEYSIG" || $2 == "REVKEYSIG" || $2 == "EXPSIG" || $2 == "BADSIG" || $2 == "ERRSIG" { bad = 1 }
    $2 == "GOODSIG" { good++ }
    $2 == "VALIDSIG" { if ($12 == primary) valid++; else bad = 1 }
    END { exit (bad || good < 1 || valid < 1) }'
}

# public_key_problem <public key file> [<signing key fingerprint>]
#
# Prints why the public key is not one to publish, and nothing when it is: no revoked subkey (rpm on
# RHEL and Rocky Linux 8 and 9 refuses to import one), and exactly one signing-capable subkey that is
# neither revoked nor expired, which is the key that signs (when a fingerprint is given, a trailing "!"
# allowed, it must be that subkey). Always succeeds: the caller tests whether the output is empty.
public_key_problem() {
  pkp_want=$(printf '%s' "${2-}" | tr 'a-f' 'A-F')
  pkp_want=${pkp_want%!}
  gpg --batch --with-colons --show-keys "$1" 2> /dev/null | awk -F: -v want="$pkp_want" '
    $1 == "pub" { cur = 0 }
    $1 == "sub" {
      if ($2 == "r") revoked++
      cur = ($2 != "r" && $2 != "e" && $12 ~ /s/)
    }
    $1 == "fpr" && cur { n++; fp = $10; cur = 0 }
    END {
      if (revoked) print "carries a revoked subkey; export it with export-public-key.sh (CONTRIBUTING.md)"
      else if (n != 1) print "does not carry exactly one signing subkey that is neither revoked nor expired (found " n + 0 ")"
      else if (want != "" && toupper(fp) != want) print "has the signing subkey " fp ", not " want
    }'
}
