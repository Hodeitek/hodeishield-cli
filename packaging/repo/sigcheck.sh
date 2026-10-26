# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
#
# Sourced by build.sh and freshness.sh, not run on its own.
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
  # On a failure the status lines go to stderr, so the log says why (they hold no key material).
  sig_status=$(gpgv --keyring "$sig_keyring" --status-fd 1 "$@" 2> /dev/null) || {
    printf '%s\n' "$sig_status" >&2
    return 1
  }
  printf '%s\n' "$sig_status" | awk -v primary="$sig_primary" '
    $1 != "[GNUPG:]" { next }
    $2 == "EXPKEYSIG" || $2 == "REVKEYSIG" || $2 == "EXPSIG" || $2 == "BADSIG" || $2 == "ERRSIG" { bad = 1 }
    $2 == "GOODSIG" { good++ }
    $2 == "VALIDSIG" { if ($12 == primary) valid++; else bad = 1 }
    END { exit (bad || good < 1 || valid < 1) }' || {
    printf '%s\n' "$sig_status" >&2
    return 1
  }
}
