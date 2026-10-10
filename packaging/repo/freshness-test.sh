#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
#
# Proves that freshness.sh goes red, and that live.sh (which decides whether there is anything to
# check) is inert only when the domain serves nothing: builds small APT and DNF repositories with a throwaway key made
# here (nothing secret, nothing real), serves them from localhost and runs freshness.sh against them.
# A repository that is up to date must pass, and every case in which it is stale, altered, unsigned,
# missing or unreachable must fail, with the status expected for it (3 for stale, 1 for the rest).
# For live.sh: no index at all (every entry point a clean 404) is inert (10); a fetch error that is not
# a 404 (500, a redirect, a refused connection) and a served index without the key are red (1).
#
#   freshness-test.sh
#
# The signature cases use throwaway keys made with gpg's faked system time: one whose signing subkey
# has expired, one whose signing subkey is revoked, and two that expire within 60 days (a warning, 5).
#
# Needs curl, gpg, gpgv, gzip, python3 and the tools freshness.sh needs. The indexes are written by
# hand in the structure that apt-ftparchive and createrepo_c produce (the repository builder's own
# output is checked by build.sh when the repositories are published).

set -eu

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
GNUPGHOME=$work/gnupg
export GNUPGHOME
mkdir -m 700 "$GNUPGHOME"
www=$work/www
mkdir "$www"
server=
servers=

cleanup() {
  [ -z "$server" ] || kill "$server" 2> /dev/null || true
  for pid in $servers; do kill "$pid" 2> /dev/null || true; done
  gpgconf --homedir "$GNUPGHOME" --kill all 2> /dev/null || true
  # The throwaway secret keys are overwritten before they are removed.
  find "$GNUPGHOME" -type f -exec shred -u {} + 2> /dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

die() {
  printf 'freshness-test.sh: %s\n' "$*" >&2
  exit 1
}

# --- Keys: the repository key, with a signing subkey as in production, and another one ----------------
gpg --batch --quiet --passphrase '' --quick-generate-key 'Freshness test <test@example.invalid>' ed25519 cert never
repo_fpr=$(gpg --batch --with-colons --list-keys | awk -F: '$1 == "fpr" { print $10; exit }')
gpg --batch --quiet --passphrase '' --quick-add-key "$repo_fpr" ed25519 sign never
repo_sub=$(gpg --batch --with-colons --list-keys "$repo_fpr" | awk -F: '$1 == "sub" { s = 1 } $1 == "fpr" && s { print $10; exit }')
gpg --batch --quiet --armor --export "$repo_fpr" > "$work/repo.asc"
gpg --batch --quiet --passphrase '' --quick-generate-key 'Other test <other@example.invalid>' ed25519 sign never
other_fpr=$(gpg --batch --with-colons --list-keys other@example.invalid | awk -F: '$1 == "fpr" { print $10; exit }')
gpg --batch --quiet --armor --export "$other_fpr" > "$work/other.asc"
signer=$repo_sub

# gpg with a faked clock when $faked is set (a time as YYYYMMDDTHHMMSS), for keys that have to be
# expired now but valid when they signed.
faked=
gpgt() {
  if [ -n "$faked" ]; then gpg --faked-system-time "$faked" "$@"; else gpg "$@"; fi
}
# newkey <email> <time> <primary expiry> <subkey expiry>: a key made at <time> ("" for now).
newkey() {
  faked=$2
  gpgt --batch --quiet --passphrase '' --quick-generate-key "Test <$1>" ed25519 cert "$3"
  fpr=$(gpg --batch --with-colons --list-keys "$1" | awk -F: '$1 == "fpr" { print $10; exit }')
  gpgt --batch --quiet --passphrase '' --quick-add-key "$fpr" ed25519 sign "$4"
  sub=$(gpg --batch --with-colons --list-keys "$fpr" | awk -F: '$1 == "sub" { s = 1 } $1 == "fpr" && s { print $10; exit }')
  faked=
}
# The signing subkey expired at the beginning of 2021; the signatures were made in 2020.
newkey expired@example.invalid 20200101T000000 never 1y
expired_fpr=$fpr
expired_sub=$sub
gpg --batch --quiet --armor --export "$expired_fpr" > "$work/expired.asc"
# The signing subkey is revoked after the signatures were made.
newkey revoked@example.invalid "" never never
revoked_fpr=$fpr
revoked_sub=$sub
# Expire within 60 days: the signing subkey, and the primary key.
newkey soon-sub@example.invalid "" 2y 30d
soon_sub_fpr=$fpr
soon_sub_sub=$sub
gpg --batch --quiet --armor --export "$soon_sub_fpr" > "$work/soon-sub.asc"
newkey soon-primary@example.invalid "" 30d 2y
soon_primary_fpr=$fpr
soon_primary_sub=$sub
gpg --batch --quiet --armor --export "$soon_primary_fpr" > "$work/soon-primary.asc"
# Expires in more than 60 days: no warning.
newkey later@example.invalid "" 2y 2y
later_fpr=$fpr
later_sub=$sub
gpg --batch --quiet --armor --export "$later_fpr" > "$work/later.asc"

# --- Fixtures ----------------------------------------------------------------------------------------
# mk <dir> <APT versions> <DNF versions>: both repositories, each listing those versions of the
# package (a version is "0.2.1"; the packages are built with release 1), signed by $signer!.
mk() {
  dir=$1
  for arch in amd64 arm64; do
    d=$dir/apt/dists/stable/main/binary-$arch
    mkdir -p "$d/by-hash/SHA256"
    # Another package, which must not count.
    printf 'Package: other-tool\nArchitecture: %s\nVersion: 99.0.0-1\n\n' "$arch" > "$d/Packages"
    for v in $2; do
      {
        printf 'Package: hodeishield\nArchitecture: %s\nVersion: %s-1\nPriority: optional\nSection: utils\n' "$arch" "$v"
        printf 'Maintainer: Hodeitek S.L. <info@hodeitek.com>\nInstalled-Size: 10402\n'
        printf 'Filename: pool/main/h/hodeishield/hodeishield_%s-1_%s.deb\nSize: 3804632\n' "$v" "$arch"
        printf 'SHA256: %s\nDescription: Read-only command-line client for HodeiShield.\n\n' \
          "$(printf '%s%s' "$v" "$arch" | sha256sum | cut -d' ' -f1)"
      } >> "$d/Packages"
    done
    gzip -9nkf "$d/Packages"
    cp "$d/Packages" "$d/by-hash/SHA256/$(sha256sum < "$d/Packages" | cut -d' ' -f1)"
  done
  {
    printf 'Acquire-By-Hash: yes\nArchitectures: amd64 arm64\nCodename: stable\nComponents: main\n'
    printf 'Date: Wed, 07 Oct 2026 13:51:15 +0000\nLabel: HodeiShield\nOrigin: HodeiShield\nSuite: stable\nSHA256:\n'
    for arch in amd64 arm64; do
      for f in Packages Packages.gz; do
        file=$dir/apt/dists/stable/main/binary-$arch/$f
        printf ' %s %16d main/binary-%s/%s\n' "$(sha256sum < "$file" | cut -d' ' -f1)" "$(stat -c %s "$file")" "$arch" "$f"
      done
    done
  } > "$dir/apt/dists/stable/Release"
  gpgt --batch --yes --local-user "$signer!" --digest-algo SHA512 --clearsign \
    --output "$dir/apt/dists/stable/InRelease" "$dir/apt/dists/stable/Release"

  for arch in x86_64 aarch64; do
    d=$dir/rpm/$arch/repodata
    mkdir -p "$d"
    {
      printf '<?xml version="1.0" encoding="UTF-8"?>\n'
      printf '<metadata xmlns="http://linux.duke.edu/metadata/common" xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="3">\n'
      printf '<package type="rpm">\n  <name>other-tool</name>\n  <arch>%s</arch>\n' "$arch"
      printf '  <version epoch="0" ver="99.0.0" rel="1"/>\n</package>\n'
      for v in $3; do
        printf '<package type="rpm">\n  <name>hodeishield</name>\n  <arch>%s</arch>\n' "$arch"
        printf '  <version epoch="0" ver="%s" rel="1"/>\n' "$v"
        printf '  <checksum type="sha256" pkgid="YES">%s</checksum>\n' "$(printf '%s%s' "$v" "$arch" | sha256sum | cut -d' ' -f1)"
        printf '  <location href="hodeishield-%s-1.%s.rpm"/>\n  <format>\n    <rpm:provides>\n' "$v" "$arch"
        printf '      <rpm:entry name="hodeishield" flags="EQ" epoch="0" ver="%s" rel="1"/>\n' "$v"
        printf '    </rpm:provides>\n  </format>\n</package>\n'
      done
      printf '</metadata>\n'
    } > "$d/primary.xml"
    gzip -9nc "$d/primary.xml" > "$d/primary.xml.gz"
    sha=$(sha256sum < "$d/primary.xml.gz" | cut -d' ' -f1)
    open=$(sha256sum < "$d/primary.xml" | cut -d' ' -f1)
    mv "$d/primary.xml.gz" "$d/$sha-primary.xml.gz"
    rm "$d/primary.xml"
    {
      printf '<?xml version="1.0" encoding="UTF-8"?>\n'
      printf '<repomd xmlns="http://linux.duke.edu/metadata/repo" xmlns:rpm="http://linux.duke.edu/metadata/rpm">\n'
      printf '  <revision>1791381076</revision>\n'
      printf '  <data type="primary">\n    <checksum type="sha256">%s</checksum>\n' "$sha"
      printf '    <open-checksum type="sha256">%s</open-checksum>\n' "$open"
      printf '    <location href="repodata/%s-primary.xml.gz"/>\n    <timestamp>1791381076</timestamp>\n' "$sha"
      printf '    <size>%s</size>\n  </data>\n' "$(stat -c %s "$d/$sha-primary.xml.gz")"
      printf '  <data type="filelists">\n    <checksum type="sha256">%s</checksum>\n' "$(printf filelists | sha256sum | cut -d' ' -f1)"
      printf '    <location href="repodata/%s-filelists.xml.gz"/>\n  </data>\n</repomd>\n' "$(printf filelists | sha256sum | cut -d' ' -f1)"
    } > "$d/repomd.xml"
    gpgt --batch --yes --local-user "$signer!" --digest-algo SHA512 --armor --detach-sign \
      --output "$d/repomd.xml.asc" "$d/repomd.xml"
  done
}

# The hash-named copy of the Packages file of an architecture in <dir>.
byhash() {
  find "$1/apt/dists/stable/main/binary-$2/by-hash/SHA256" -type f | while read -r f; do
    if [ "$(sha256sum < "$1/apt/dists/stable/main/binary-$2/Packages" | cut -d' ' -f1)" = "$(basename "$f")" ]; then
      printf '%s\n' "$f"
    fi
  done
}

# --- The repositories under test ---------------------------------------------------------------------
# Versions 0.9.0 and 0.10.0 are there to be told apart by version order, not by text.
mk "$www/fresh" "0.9.0 0.10.0" "0.10.0 0.9.0"
mk "$www/stale-apt" "0.9.0" "0.9.0 0.10.0"
mk "$www/stale-dnf" "0.9.0 0.10.0" "0.9.0"
mk "$www/no-package" "" "0.9.0 0.10.0"
signer=$other_fpr
mk "$www/other-key" "0.9.0 0.10.0" "0.9.0 0.10.0"
signer=$repo_sub

signer=$expired_sub
faked=20200601T120000
mk "$www/expired-key" "0.9.0 0.10.0" "0.9.0 0.10.0"
faked=
signer=$revoked_sub
mk "$www/revoked-key" "0.9.0 0.10.0" "0.9.0 0.10.0"
# The revocation of the subkey (reason 0, no text), after it signed.
printf 'key 1\nrevkey\ny\n0\n\ny\nsave\n' |
  gpg --batch --yes --command-fd 0 --status-fd 2 --edit-key "$revoked_fpr" 2> "$work/revoke.log" ||
  die "cannot revoke the test subkey"
gpg --batch --quiet --armor --export "$revoked_fpr" > "$work/revoked.asc"
signer=$soon_sub_sub
mk "$www/soon-sub" "0.9.0 0.10.0" "0.9.0 0.10.0"
signer=$soon_primary_sub
mk "$www/soon-primary" "0.9.0 0.10.0" "0.9.0 0.10.0"
signer=$later_sub
mk "$www/later" "0.9.0 0.10.0" "0.9.0 0.10.0"
signer=$repo_sub

cp -R "$www/fresh" "$www/tampered-inrelease"
sed -i 's/^Suite: stable$/Suite: stablf/' "$www/tampered-inrelease/apt/dists/stable/InRelease"

cp -R "$www/fresh" "$www/text-after-signature"
printf 'Acquire-By-Hash: yes\n' >> "$www/text-after-signature/apt/dists/stable/InRelease"

cp -R "$www/fresh" "$www/two-messages"
cat "$www/stale-apt/apt/dists/stable/InRelease" "$www/fresh/apt/dists/stable/InRelease" \
  > "$www/two-messages/apt/dists/stable/InRelease"

cp -R "$www/fresh" "$www/tampered-repomd"
sed -i 's|<revision>1791381076|<revision>1791381077|' "$www/tampered-repomd/rpm/aarch64/repodata/repomd.xml"

cp -R "$www/fresh" "$www/bad-asc"
cp "$www/other-key/rpm/x86_64/repodata/repomd.xml.asc" "$www/bad-asc/rpm/x86_64/repodata/repomd.xml.asc"

cp -R "$www/fresh" "$www/no-asc"
rm "$www/no-asc/rpm/x86_64/repodata/repomd.xml.asc"

# An older signed index whose Packages (by hash) has been swapped for the current one.
cp -R "$www/stale-apt" "$www/packages-swapped"
cp "$(byhash "$www/fresh" amd64)" "$(byhash "$www/packages-swapped" amd64)"

# The same for the DNF primary data.
cp -R "$www/stale-dnf" "$www/primary-swapped"
cp "$www"/fresh/rpm/x86_64/repodata/*-primary.xml.gz "$(ls "$www"/primary-swapped/rpm/x86_64/repodata/*-primary.xml.gz)"

# --- The server ---------------------------------------------------------------------------------------
python3 -I -u -m http.server 0 --bind 127.0.0.1 --directory "$www" > "$work/server.log" 2>&1 &
server=$!
port=
i=0
while [ -z "$port" ] && [ "$i" -lt 50 ]; do
  port=$(sed -n 's/.* port \([0-9][0-9]*\) .*/\1/p' "$work/server.log")
  i=$((i + 1))
  [ -n "$port" ] || sleep 0.1
done
[ -n "$port" ] || die "the test server did not start"
url=http://127.0.0.1:$port

# A server that answers every request with the status <code> (and a redirect to nowhere for 301).
# start_status <code> sets $status_url.
start_status() {
  : > "$work/status.log"
  python3 -I -u -c '
import http.server, sys
code = int(sys.argv[1])
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(code)
        if code == 301:
            self.send_header("Location", "http://127.0.0.1:1/")
        self.send_header("Content-Length", "0")
        self.end_headers()
    def log_message(self, *args):
        pass
s = http.server.HTTPServer(("127.0.0.1", 0), H)
print(s.server_address[1], flush=True)
s.serve_forever()' "$1" > "$work/status.log" &
  servers="$servers $!"
  sp=
  i=0
  while [ -z "$sp" ] && [ "$i" -lt 50 ]; do
    sp=$(sed -n '1p' "$work/status.log")
    i=$((i + 1))
    [ -n "$sp" ] || sleep 0.1
  done
  [ -n "$sp" ] || die "the status server did not start"
  status_url=http://127.0.0.1:$sp
}
start_status 500
url500=$status_url
start_status 403
url403=$status_url
start_status 301
url301=$status_url

# Only the APT repository is served: the DNF entry points answer 404.
cp -R "$www/fresh" "$www/apt-only"
rm -r "$www/apt-only/rpm"

# --- The cases ---------------------------------------------------------------------------------------
FRESHNESS_ALLOW_HTTP=1
FRESHNESS_RETRIES=0
export FRESHNESS_ALLOW_HTTP FRESHNESS_RETRIES
bad=0
printf '%-34s %-6s %-6s %-6s %s\n' CASE WANT GOT RESULT WHY

# check <name> <wanted status> <base URL> <expected version> <public key>
check() {
  status=0
  sh "$here/freshness.sh" "$3" "$4" "$5" > "$work/out" 2>&1 || status=$?
  if [ "$status" = "$2" ]; then result=ok; else result=WRONG; bad=1; fi
  printf '%-34s %-6s %-6s %-6s %s\n' "$1" "$2" "$status" "$result" "$(sed -n 's/^freshness.sh: //p' "$work/out" | head -n 1)"
  [ "$result" = ok ] || sed 's/^/    /' "$work/out"
}

check 'fresh' 0 "$url/fresh" 0.10.0 "$work/repo.asc"
check 'stale APT' 3 "$url/stale-apt" 0.10.0 "$work/repo.asc"
check 'stale DNF' 3 "$url/stale-dnf" 0.10.0 "$work/repo.asc"
check 'a release not served yet' 3 "$url/fresh" 0.11.0 "$work/repo.asc"
check 'newer than the release' 1 "$url/fresh" 0.9.0 "$work/repo.asc"
check 'no hodeishield in APT' 1 "$url/no-package" 0.10.0 "$work/repo.asc"
check 'tampered InRelease' 1 "$url/tampered-inrelease" 0.10.0 "$work/repo.asc"
check 'text after the signature' 1 "$url/text-after-signature" 0.10.0 "$work/repo.asc"
check 'two signed messages' 1 "$url/two-messages" 0.10.0 "$work/repo.asc"
check 'signed by another key' 1 "$url/other-key" 0.10.0 "$work/repo.asc"
check 'checked with another key' 1 "$url/fresh" 0.10.0 "$work/other.asc"
check 'signed by an expired key' 1 "$url/expired-key" 0.10.0 "$work/expired.asc"
check 'signed by a revoked subkey' 1 "$url/revoked-key" 0.10.0 "$work/revoked.asc"
# These two are only a real test if gpgv itself accepts them (exit 0) and says why on the status fd.
rawstatus() {
  gpg --batch --yes --quiet --dearmor --output "$work/raw.gpg" "$2"
  st=0
  gpgv --keyring "$work/raw.gpg" --status-fd 1 "$www/$1/apt/dists/stable/InRelease" > "$work/raw.out" 2> /dev/null || st=$?
  if [ "$st" = 0 ] && grep -q "^\[GNUPG:\] $3 " "$work/raw.out"; then
    printf '%-34s gpgv exits 0 and reports %s\n' "  ($1)" "$3"
  else
    printf '%-34s WRONG: gpgv exit %s, no %s\n' "  ($1)" "$st" "$3"
    bad=1
  fi
}
rawstatus expired-key "$work/expired.asc" EXPKEYSIG
rawstatus revoked-key "$work/revoked.asc" REVKEYSIG
check 'subkey expires within 60 days' 5 "$url/soon-sub" 0.10.0 "$work/soon-sub.asc"
check 'primary expires within 60 days' 5 "$url/soon-primary" 0.10.0 "$work/soon-primary.asc"
check 'expiring key and a stale index' 3 "$url/soon-sub" 0.11.0 "$work/soon-sub.asc"
check 'key expires in over 60 days' 0 "$url/later" 0.10.0 "$work/later.asc"
check 'tampered repomd.xml' 1 "$url/tampered-repomd" 0.10.0 "$work/repo.asc"
check 'bad repomd.xml.asc' 1 "$url/bad-asc" 0.10.0 "$work/repo.asc"
check 'missing repomd.xml.asc' 1 "$url/no-asc" 0.10.0 "$work/repo.asc"
check 'Packages hash mismatch' 1 "$url/packages-swapped" 0.10.0 "$work/repo.asc"
check 'primary.xml.gz hash mismatch' 1 "$url/primary-swapped" 0.10.0 "$work/repo.asc"
check 'not found' 1 "$url/nowhere" 0.10.0 "$work/repo.asc"
check 'server unreachable' 1 http://127.0.0.1:1 0.10.0 "$work/repo.asc"
check 'no public key' 1 "$url/fresh" 0.10.0 "$work/missing.asc"
FRESHNESS_ALLOW_HTTP=0
check 'plain http not allowed' 1 "$url/fresh" 0.10.0 "$work/repo.asc"

# checklive <name> <wanted status> <base URL> <public key> [<text the output must contain>]
checklive() {
  status=0
  sh "$here/live.sh" "$3" "$4" > "$work/out" 2>&1 || status=$?
  if [ "$status" = "$2" ] && { [ -z "${5:-}" ] || grep -Fq -- "$5" "$work/out"; }; then result=ok; else result=WRONG; bad=1; fi
  printf '%-34s %-6s %-6s %-6s %s\n' "$1" "$2" "$status" "$result" "$(sed -n 's/^live.sh: //p' "$work/out" | head -n 1)"
  [ "$result" = ok ] || sed 's/^/    /' "$work/out"
}

FRESHNESS_ALLOW_HTTP=1
printf '\n%-34s %-6s %-6s %-6s %s\n' 'LIVE CASE' WANT GOT RESULT WHY
# Nothing served: inert, with or without a key.
checklive 'domain serves nothing (all 404)' 10 "$url/nowhere" "$work/repo.asc"
checklive 'serves nothing, no key' 10 "$url/nowhere" "$work/missing.asc"
# An index is served.
checklive 'live repo, key present' 0 "$url/fresh" "$work/repo.asc"
checklive 'live repo, key missing' 1 "$url/fresh" "$work/missing.asc" 'the repositories are live but the public key'
: > "$work/empty.asc"
checklive 'live repo, key empty' 1 "$url/fresh" "$work/empty.asc" 'the repositories are live but the public key'
mkdir "$work/keydir"
checklive 'live repo, key is a directory' 1 "$url/fresh" "$work/keydir"
checklive 'only APT served, key missing' 1 "$url/apt-only" "$work/missing.asc"
checklive 'only APT served, key present' 0 "$url/apt-only" "$work/repo.asc"
# Anything but a clean 404 is red, whether or not the key is there.
checklive 'fetch error: HTTP 500' 1 "$url500" "$work/repo.asc" 'answered HTTP 500'
checklive 'fetch error: HTTP 500, no key' 1 "$url500" "$work/missing.asc" 'answered HTTP 500'
checklive 'fetch error: HTTP 403' 1 "$url403" "$work/missing.asc"
checklive 'fetch error: redirect' 1 "$url301" "$work/missing.asc"
checklive 'fetch error: refused' 1 http://127.0.0.1:1 "$work/missing.asc" 'cannot reach'
FRESHNESS_ALLOW_HTTP=0
checklive 'plain http not allowed' 1 "$url/nowhere" "$work/repo.asc"
[ "$bad" = 0 ] || exit 1
echo "All cases behave as expected."
