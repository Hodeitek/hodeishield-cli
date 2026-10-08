#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
#
# Security tests of the repository builder (build.sh and publish.sh). They run in CI only, in the
# repository-builder-tests workflow: the cases that must be refused plant forged packages and indexes
# in a bucket on purpose, and nothing here is meant to be run by hand.
#
#   repo-test.sh
#
# Environment:
#   NFPM          absolute path to the nfpm binary (the version pinned in the workflow)
#
# Everything is made here and thrown away: the signing keys (a certify-only RSA 4096 primary with a
# signing subkey, like the real one, and a second key for the forgeries), synthetic hodeishield
# packages built with nfpm from a one-line program, and a MinIO whose publishing user may list, read
# and write but not delete (built from source: repo-test-minio.Dockerfile). The real build.sh and publish.sh run in the image named in
# packaging/repo/image. The bucket is then served over HTTP to an apt and a dnf client.
#
# Every case has an expected outcome, and the run fails if any case ends otherwise:
#   - publishing a valid release must work (into an empty bucket, on top, again, and a third time);
#   - the builder must refuse a bucket that holds anything the signed index does not vouch for, an
#     index that is not the signed one, or a release that is not the hodeishield package, and then
#     leave the bucket exactly as it was;
#   - the clients must refuse a tampered index, a corrupt package and a package that is not signed
#     with the repository key, and must install and upgrade from the untampered repository.

set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
: "${NFPM:?}"
for need in docker jq curl gzip sha256sum; do
  command -v "$need" > /dev/null || {
    printf 'repo-test.sh: %s is required\n' "$need" >&2
    exit 2
  }
done
# shellcheck source=/dev/null
. "$here/image"

builder=rt-builder
net=rt-net
minio=rt-minio
mcbox=rt-mc
rootuser=rtroot
rootpass="rtroot-secret-123"
pubuser=pubuser
pubpass="pubuser-secret-123"
srv=http://$minio:9000

uid=$(id -u)
gid=$(id -g)
work=$(mktemp -d "${TMPDIR:-/tmp}/repo-test.XXXXXX")
results=$work/results.tsv
: > "$results"
failed=0
mkdir -p "$work/bin" "$work/t"

# Only the cases that must pass, to check the harness itself.
positive_only=${REPO_TEST_POSITIVE_ONLY:-}

print_table() {
  [ -s "$results" ] || return 0
  printf '\n%-6s %-62s %-46s %s\n' RESULT CASE EXPECTED GOT
  awk -F'\t' '{ printf "%-6s %-62s %-46s %s\n", $4, $1, $2, $3 }' "$results"
  printf '\n%s cases, %s failed\n' "$(wc -l < "$results" | tr -d ' ')" \
    "$(awk -F'\t' '$4 == "FAIL" { n++ } END { print n + 0 }' "$results")"
}

cleanup() {
  status=$?
  trap - EXIT
  print_table
  docker rm -f "$minio" "$mcbox" > /dev/null 2>&1 || true
  docker network rm "$net" > /dev/null 2>&1 || true
  rm -rf "$work"
  if [ "$status" = 0 ] && [ "$failed" != 0 ]; then
    status=1
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

group() { printf '::group::%s\n' "$*"; }
endgroup() { printf '::endgroup::\n'; }

# A path under $work, as the containers see it (they mount $work at /w).
inw() { printf '/w/%s' "${1#"$work"/}"; }

# record <case> <expected> <got> <PASS|FAIL>
record() {
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$results"
  if [ "$4" != PASS ]; then
    failed=1
    printf '::error::%s: expected %s, got %s\n' "$1" "$2" "$3"
  fi
}

# --- The builder image ---------------------------------------------------------------------------------
group "Build the repository image"
# shellcheck disable=SC2153
docker build --quiet --tag "$builder" - << EOF
FROM $IMAGE
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends $PACKAGES \
  && rm -rf /var/lib/apt/lists/*
EOF
endgroup

# Runs a command in the builder image, with $work at /w.
tool() {
  docker run --rm --user "$uid:$gid" --env HOME=/tmp --volume "$work:/w" --workdir /w "$builder" "$@"
}

# --- Helper scripts that run in the builder image -----------------------------------------------------
cat > "$work/bin/keys.sh" << 'EOF'
set -eu
export HOME=/tmp
quiet() { gpg --batch --quiet --pinentry-mode loopback --passphrase '' "$@"; }
fingerprint() { gpg --batch --with-colons --list-keys | awk -F: '$1 == "fpr" { print $10; exit }'; }

# The repository key: a primary that can only certify, and a signing subkey. Only the subkey's secret
# part reaches the keyring that the builder uses.
GNUPGHOME=/w/gnupg-primary
export GNUPGHOME
mkdir -m 700 "$GNUPGHOME"
quiet --quick-generate-key 'HodeiShield repository test key <repo-test@example.invalid>' rsa4096 cert never
primary=$(fingerprint)
quiet --quick-add-key "$primary" rsa4096 sign never
gpg --batch --armor --export "$primary" > /w/pub.asc
quiet --export-secret-subkeys "$primary" > /w/subkey.gpg
gpgconf --kill all

GNUPGHOME=/w/gnupg-sign
export GNUPGHOME
mkdir -m 700 "$GNUPGHOME"
gpg --batch --quiet --import /w/subkey.gpg
sub=$(gpg --batch --with-colons --list-secret-keys |
  awk -F: '$1 == "ssb" { sign = ($12 ~ /s/) } $1 == "fpr" && sign { print $10; sign = 0 }')
[ "$(printf '%s\n' "$sub" | grep -c .)" = 1 ]
printf '%s!\n' "$sub" > /w/signing_key
gpgconf --kill all
rm -f /w/subkey.gpg

# Another key, for forgeries.
GNUPGHOME=/w/gnupg-evil
export GNUPGHOME
mkdir -m 700 "$GNUPGHOME"
quiet --quick-generate-key 'Another key <other@example.invalid>' rsa2048 sign never
other=$(fingerprint)
printf '%s\n' "$other" > /w/evil.fpr
gpg --batch --armor --export "$other" > /w/evil.asc
gpgconf --kill all
EOF

# signrpm.sh <gnupghome> <key> <public key> <rpm>...
cat > "$work/bin/signrpm.sh" << 'EOF'
set -eu
export HOME=/tmp
home=$1 key=$2 pub=$3
shift 3
db=$(mktemp -d)
trap 'rm -rf "$db"' EXIT
rpm --dbpath "$db" --import "$pub"
GNUPGHOME=$home rpmsign --define "_dbpath $db" --define "_gpg_name $key" \
  --define "_gpg_digest_algo sha512" --addsign "$@" > /dev/null
EOF

# rpmrepo.sh <dir>: a DNF repository of the packages in <dir>, with repomd.xml signed by the repository key.
cat > "$work/bin/rpmrepo.sh" << 'EOF'
set -eu
export HOME=/tmp GNUPGHOME=/w/gnupg-sign
createrepo_c --quiet --no-database --general-compress-type=gz "$1"
gpg --batch --yes --local-user "$(cat /w/signing_key)" --digest-algo SHA512 --armor --detach-sign \
  --output "$1/repodata/repomd.xml.asc" "$1/repodata/repomd.xml"
EOF

# evilsign.sh <in> <out>: clear-signs a file with the other key.
cat > "$work/bin/evilsign.sh" << 'EOF'
set -eu
export HOME=/tmp GNUPGHOME=/w/gnupg-evil
gpg --batch --yes --local-user "$(cat /w/evil.fpr)" --digest-algo SHA512 --clearsign --output "$2" "$1"
EOF

# --- Client scripts (run as root in the apt and dnf containers) --------------------------------------
cat > "$work/bin/apt-client.sh" << 'EOF'
# apt-client.sh ok <url 1> <url 2> <version 1> <version 2>
# apt-client.sh refuse <index|package> <url> [<pattern>]
set -u
export DEBIAN_FRONTEND=noninteractive
only="-o Dir::Etc::sourcelist=/etc/apt/sources.list.d/hodeishield.list -o Dir::Etc::sourceparts=/nonexistent"
setup() {
  mkdir -p /etc/apt/keyrings
  curl -fsS "$1/gpg.key" -o /etc/apt/keyrings/hodeishield.asc || { echo "SETUP: cannot fetch the key"; exit 90; }
  echo "deb [signed-by=/etc/apt/keyrings/hodeishield.asc] $1/apt stable main" > /etc/apt/sources.list.d/hodeishield.list
}
mode=$1
shift
case $mode in
ok)
  set -e
  setup "$1"
  apt-get $only update
  apt-get $only install -y hodeishield
  [ "$(hodeishield --version)" = "hodeishield $3" ]
  setup "$2"
  apt-get $only update
  apt-get $only install -y --only-upgrade hodeishield
  [ "$(hodeishield --version)" = "hodeishield $4" ]
  echo "OK: installed $3 and upgraded to $4, with the repository's signatures checked"
  ;;
refuse)
  kind=$1 url=$2 pattern=${3:-.}
  setup "$url"
  out=$(apt-get $only update 2>&1)
  rc=$?
  echo "$out"
  if [ "$kind" = index ]; then
    [ "$rc" != 0 ] || { echo "NOT REFUSED: apt-get update accepted the index"; exit 1; }
  else
    [ "$rc" = 0 ] || { echo "SETUP: apt-get update failed on a valid index"; exit 1; }
  fi
  out2=$(apt-get $only install -y hodeishield 2>&1)
  rc2=$?
  echo "$out2"
  [ "$rc2" != 0 ] || { echo "NOT REFUSED: hodeishield was installed"; exit 1; }
  if dpkg -s hodeishield > /dev/null 2>&1; then
    echo "NOT REFUSED: hodeishield is installed"
    exit 1
  fi
  line=$(printf '%s\n%s\n' "$out" "$out2" | grep -E "$pattern" | head -n 1)
  [ -n "$line" ] || { echo "NOT REFUSED FOR THE EXPECTED REASON"; exit 1; }
  echo "REFUSED: $line"
  ;;
esac
EOF

cat > "$work/bin/dnf-client.sh" << 'EOF'
# dnf-client.sh ok <url 1> <url 2> <version 1> <version 2>
# dnf-client.sh refuse <index|package> <url> [<pattern>]
set -uf
dnfq="dnf -y --disablerepo=* --enablerepo=hodeishield"
repo=/etc/yum.repos.d/hodeishield.repo
setup() {
  curl -fsS "$1/rpm/hodeishield.repo" -o "$repo" || { echo "SETUP: cannot fetch the .repo file"; exit 90; }
  sed -i "s#https://packages.hodeishield.com#$1#g" "$repo"
  grep -qx 'gpgcheck=1' "$repo" && grep -qx 'repo_gpgcheck=1' "$repo" || { echo "SETUP: signature checks are off"; exit 90; }
}
mode=$1
shift
case $mode in
ok)
  set -e
  setup "$1"
  $dnfq install hodeishield
  [ "$(hodeishield --version)" = "hodeishield $3" ]
  sed -i "s#$1#$2#g" "$repo"
  dnf clean all
  $dnfq upgrade --refresh hodeishield
  [ "$(hodeishield --version)" = "hodeishield $4" ]
  grep -qx 'gpgcheck=1' "$repo" && grep -qx 'repo_gpgcheck=1' "$repo"
  echo "OK: installed $3 and upgraded to $4, with gpgcheck and repo_gpgcheck on"
  ;;
refuse)
  kind=$1 url=$2 pattern=${3:-.}
  setup "$url"
  out=$($dnfq makecache 2>&1)
  rc=$?
  echo "$out"
  if [ "$kind" = index ]; then
    [ "$rc" != 0 ] || { echo "NOT REFUSED: dnf accepted the metadata"; exit 1; }
  else
    [ "$rc" = 0 ] || { echo "SETUP: dnf could not read valid metadata"; exit 1; }
  fi
  out2=$($dnfq install hodeishield 2>&1)
  rc2=$?
  echo "$out2"
  [ "$rc2" != 0 ] || { echo "NOT REFUSED: hodeishield was installed"; exit 1; }
  if rpm -q hodeishield > /dev/null 2>&1; then
    echo "NOT REFUSED: hodeishield is installed"
    exit 1
  fi
  line=$(printf '%s\n%s\n' "$out" "$out2" | grep -E "$pattern" | head -n 1)
  [ -n "$line" ] || { echo "NOT REFUSED FOR THE EXPECTED REASON"; exit 1; }
  echo "REFUSED: $line"
  ;;
esac
EOF

# --- Keys ------------------------------------------------------------------------------------------------
group "Throwaway keys"
tool sh /w/bin/keys.sh
signing_key=$(cat "$work/signing_key")
find "$work" -maxdepth 1 -type f | sort | tr '\n' ' '
printf '\nsigning subkey %s\n' "$signing_key"
endgroup

# --- Packages ------------------------------------------------------------------------------------------
# mkpkgs <out dir> <name> <version> <what the program prints>: .deb and .rpm for amd64 and arm64.
mkpkgs() {
  out=$1 name=$2 version=$3 says=$4
  config=$root/packaging/nfpm.yaml
  if [ "$name" != hodeishield ]; then
    config=$work/nfpm-$name.yaml
    sed "s/^name: hodeishield\$/name: $name/" "$root/packaging/nfpm.yaml" > "$config"
  fi
  stage=$(mktemp -d "$work/stage.XXXXXX")
  mkdir -p "$stage/man" "$stage/completions" "$out"
  printf '#!/bin/sh\necho "%s"\n' "$says" > "$stage/hodeishield"
  chmod 755 "$stage/hodeishield"
  printf '.TH HODEISHIELD 1\n' | gzip -9n > "$stage/man/hodeishield.1.gz"
  for completion in hodeishield.bash _hodeishield hodeishield.fish; do
    printf '# test\n' > "$stage/completions/$completion"
  done
  cp "$root/LICENSE" "$root/NOTICE" "$stage/"
  for arch in amd64 arm64; do
    for packager in deb rpm; do
      (cd "$stage" && VERSION=$version ARCH=$arch "$NFPM" package -f "$config" -p "$packager" -t "$out/" > /dev/null)
    done
  done
  rm -rf "$stage"
}

group "Synthetic packages"
pk=$work/pk
mkpkgs "$pk/v1" hodeishield 0.2.0 "hodeishield 0.2.0"
mkpkgs "$pk/v2" hodeishield 0.2.1 "hodeishield 0.2.1"
mkpkgs "$pk/v3" hodeishield 0.2.2 "hodeishield 0.2.2"
ls "$pk/v1" "$pk/v2" "$pk/v3"
endgroup

# --- MinIO ------------------------------------------------------------------------------------------------
group "MinIO"
docker build --quiet --tag rt-minio-image --build-arg BASE="$IMAGE" - < "$here/repo-test-minio.Dockerfile" > /dev/null
docker network create "$net" > /dev/null
docker run -d --name "$minio" --network "$net" --env MINIO_ROOT_USER="$rootuser" \
  --env MINIO_ROOT_PASSWORD="$rootpass" rt-minio-image minio server /data > /dev/null
docker run -d --name "$mcbox" --network "$net" --user "$uid:$gid" --env MC_CONFIG_DIR=/tmp/mc \
  --volume "$work:/w" rt-minio-image sleep 86400 > /dev/null
mcx() { docker exec "$mcbox" mc "$@"; }
tries=0
until mcx alias set r "$srv" "$rootuser" "$rootpass" > /dev/null 2>&1; do
  tries=$((tries + 1))
  [ "$tries" -lt 60 ] || {
    echo "repo-test.sh: MinIO did not start" >&2
    docker logs "$minio" >&2
    exit 1
  }
  sleep 1
done
# The publishing user may list, read and write, never delete (like the real one).
cat > "$work/policy.json" << 'EOF'
{"Version": "2012-10-17", "Statement": [
  {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": ["arn:aws:s3:::rt-*"]},
  {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": ["arn:aws:s3:::rt-*/*"]}]}
EOF
mcx admin policy create r rt-nodelete /w/policy.json > /dev/null
mcx admin user add r "$pubuser" "$pubpass" > /dev/null
mcx admin policy attach r rt-nodelete --user "$pubuser" > /dev/null
mcx alias set u "$srv" "$pubuser" "$pubpass" > /dev/null
endgroup

newbucket() {
  mcx mb --quiet "r/$1" > /dev/null
  mcx anonymous set download "r/$1" > /dev/null
}
# clone <from> <to>
clone() {
  newbucket "$2"
  mcx mirror --quiet "r/$1" "r/$2" > /dev/null
}
# put <bucket> <key> <file>
put() { mcx cp --quiet "$(inw "$3")" "r/$1/$2" > /dev/null; }
# del <bucket> <key>
del() { mcx rm --quiet "r/$1/$2" > /dev/null; }
# get <bucket> <key> <file>
get() { mcx cat "r/$1/$2" > "$3"; }
# snap <bucket>: every object with its size, ETag and modification time.
snap() { mcx ls --recursive --json "r/$1" | jq -r '[.key, (.size | tostring), .etag, .lastModified] | @tsv' | sort; }
# packages_of <bucket>: the packages in the bucket.
packages_of() { snap "$1" | awk -F'\t' '$1 ~ /^apt\/pool\// || $1 ~ /^rpm\/[^\/]*\/[^\/]*\.rpm$/'; }
# hash_of <InRelease> <arch>: the SHA256 that the signed index gives for that architecture's Packages.
hash_of() {
  awk -v f="main/binary-$2/Packages" '/^[^ ]/ { s = ($0 == "SHA256:"); next } s && $3 == f { print $1 }' "$1"
}

# publish <bucket> <new packages dir>: runs publish.sh as the workflow does; sets $out and $rc.
publish() {
  rc=0
  out=$(docker run --rm --network "$net" --user "$uid:$gid" --env HOME=/tmp \
    --env PACKAGES_S3_ENDPOINT="$srv" --env PACKAGES_S3_REGION=us-east-1 --env PACKAGES_S3_BUCKET="$1" \
    --env PACKAGES_S3_ACCESS_KEY_ID="$pubuser" --env PACKAGES_S3_SECRET_ACCESS_KEY="$pubpass" \
    --env SIGNING_KEY="$signing_key" --env GNUPGHOME=/gnupg --env PUBLIC_KEY=/gpg.key \
    --volume "$work/gnupg-sign:/gnupg" --volume "$work/pub.asc:/gpg.key:ro" \
    --volume "$here:/repo:ro" --volume "$2:/new:ro" \
    "$builder" sh /repo/publish.sh /new 2>&1) || rc=$?
}

# must_publish <case> <description> <bucket> <new dir>
must_publish() {
  group "$1 $2"
  publish "$3" "$4"
  if [ "$rc" = 0 ] && printf '%s\n' "$out" | grep -q '^Repository built and verified'; then
    verdict=PASS
    got="exit 0, repository built and verified"
  else
    verdict=FAIL
    got="exit $rc"
    printf '%s\n' "$out"
  fi
  printf '%s\n' "$out" | tail -n 3
  endgroup
  record "$1 $2" "publishes" "$got" "$verdict"
}

# must_refuse <case> <description> <bucket> <message (regex)> [<new dir>]
# The bucket is as the caller left it; publishing must fail with that message and change nothing.
must_refuse() {
  id=$1 desc=$2 bucket=$3 message=$4 newdir=${5:-$pk/v3}
  group "$id $desc"
  before=$(snap "$bucket")
  publish "$bucket" "$newdir"
  after=$(snap "$bucket")
  verdict=PASS
  if [ "$rc" = 0 ]; then
    verdict=FAIL
    got="PUBLISHED (exit 0)"
  else
    got="refused (exit $rc)"
    line=$(printf '%s\n' "$out" | grep -E "$message" | head -n 1 || true)
    if [ -z "$line" ]; then
      verdict=FAIL
      got="$got, for another reason"
    fi
  fi
  if [ "$before" = "$after" ]; then
    got="$got, bucket and InRelease unchanged"
  else
    verdict=FAIL
    got="$got, BUCKET CHANGED"
    printf '%s\n' "$before" > "$work/t/before"
    printf '%s\n' "$after" > "$work/t/after"
    diff -u "$work/t/before" "$work/t/after" || true
  fi
  [ "$verdict" = PASS ] || printf '%s\n' "$out"
  printf '%s\n' "$out" | tail -n 3
  endgroup
  record "$id $desc" "refused, nothing uploaded" "$got" "$verdict"
}

# --- Must pass: publishing -------------------------------------------------------------------------------
newbucket rt-v1
must_publish P1 "release 0.2.0 into an empty bucket" rt-v1 "$pk/v1"
for key in gpg.key index.html apt/dists/stable/InRelease apt/dists/stable/Release.gpg rpm/hodeishield.repo \
  rpm/x86_64/repodata/repomd.xml.asc rpm/aarch64/repodata/repomd.xml.asc; do
  mcx stat "r/rt-v1/$key" > /dev/null 2>&1 || record "P1 $key is published" present missing FAIL
done

clone rt-v1 rt-v2
must_publish P2 "release 0.2.1 on top of 0.2.0" rt-v2 "$pk/v2"
get rt-v2 apt/pool/main/h/hodeishield/hodeishield_0.2.0-1_amd64.deb "$work/t/old.deb" ||
  record "P2 the earlier release is still there" present missing FAIL
get rt-v2 apt/dists/stable/main/binary-amd64/Packages "$work/t/Packages"
if grep -q '^Version: 0.2.0-1$' "$work/t/Packages" && grep -q '^Version: 0.2.1-1$' "$work/t/Packages"; then
  record "P2 the index lists both releases" "0.2.0 and 0.2.1" "0.2.0 and 0.2.1" PASS
else
  record "P2 the index lists both releases" "0.2.0 and 0.2.1" "see Packages" FAIL
fi

before=$(packages_of rt-v2)
must_publish P3 "release 0.2.1 again (idempotent)" rt-v2 "$pk/v2"
if [ "$before" = "$(packages_of rt-v2)" ]; then
  record "P3 published packages untouched" "same objects" "same objects" PASS
else
  record "P3 published packages untouched" "same objects" "CHANGED" FAIL
fi

clone rt-v2 rt-ctl
must_publish P4 "release 0.2.2 on the base of the refusal cases" rt-ctl "$pk/v3"

# --- Must pass: clients ----------------------------------------------------------------------------------
docker build --quiet --tag rt-apt-client - << 'EOF' > /dev/null
FROM debian:stable
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends curl ca-certificates \
  && rm -rf /var/lib/apt/lists/*
EOF

# client <apt|dnf> <case> <description> <expected> <script args...>: the script exits 0 when it got what it expected.
client() {
  kind=$1 id=$2 desc=$3 expected=$4
  shift 4
  case $kind in
    apt) image=rt-apt-client ;;
    dnf) image=rockylinux:9 ;;
  esac
  group "$id $desc"
  rc=0
  out=$(docker run --rm --network "$net" --volume "$work/bin:/b:ro" "$image" sh "/b/$kind-client.sh" "$@" 2>&1) || rc=$?
  printf '%s\n' "$out" | tail -n 40
  endgroup
  line=$(printf '%s\n' "$out" | grep -E '^(OK|REFUSED):' | tail -n 1 || true)
  if [ "$rc" = 0 ] && [ -n "$line" ]; then
    record "$id $desc" "$expected" "$(printf '%s' "$line" | cut -c1-120)" PASS
  else
    record "$id $desc" "$expected" "exit $rc: $(printf '%s\n' "$out" | tail -n 1 | cut -c1-100)" FAIL
  fi
}

client apt P5 "apt (debian:stable) installs 0.2.0, upgrades to 0.2.1" "installs and upgrades" \
  ok "$srv/rt-v1" "$srv/rt-v2" 0.2.0 0.2.1
client dnf P6 "dnf (rockylinux:9) installs 0.2.0, upgrades to 0.2.1" "installs and upgrades" \
  ok "$srv/rt-v1" "$srv/rt-v2" 0.2.0 0.2.1

if [ -n "$positive_only" ]; then
  exit 0
fi

# --- The forgeries ------------------------------------------------------------------------------------
group "Forged packages and indexes"
mkpkgs "$pk/evil" hodeishield 9.9.9 "evil"
mkpkgs "$pk/ssh" openssh-server 99.0.0 "not hodeishield"
mkpkgs "$pk/alt" hodeishield 0.2.1 "hodeishield 0.2.1 with another payload"
evil_deb=$pk/evil/hodeishield_9.9.9-1_amd64.deb
ssh_deb=$pk/ssh/openssh-server_99.0.0-1_amd64.deb
ssh_rpm=openssh-server-99.0.0-1.x86_64.rpm
# The same .rpm files signed with the repository key, and with another key.
mkdir -p "$work/ours" "$work/other"
cp "$pk/v1/hodeishield-0.2.0-1.x86_64.rpm" "$pk/ssh/$ssh_rpm" "$work/ours/"
cp "$pk/evil/hodeishield-9.9.9-1.x86_64.rpm" "$pk/v2/hodeishield-0.2.1-1.x86_64.rpm" "$work/other/"
tool sh /w/bin/signrpm.sh /w/gnupg-sign "$signing_key" /w/pub.asc \
  /w/ours/hodeishield-0.2.0-1.x86_64.rpm "/w/ours/$ssh_rpm"
tool sh /w/bin/signrpm.sh /w/gnupg-evil "$(cat "$work/evil.fpr")" /w/evil.asc \
  /w/other/hodeishield-9.9.9-1.x86_64.rpm /w/other/hodeishield-0.2.1-1.x86_64.rpm
# An index that lists an extra package, and the signed Release of the base, to forge from.
base=rt-v2
get rt-v2 apt/dists/stable/InRelease "$work/t/InRelease"
get rt-v2 apt/dists/stable/Release "$work/t/Release"
get rt-v1 apt/dists/stable/InRelease "$work/t/InRelease.old"
real_hash=$(hash_of "$work/t/InRelease" amd64)
get rt-v2 "apt/dists/stable/main/binary-amd64/by-hash/SHA256/$real_hash" "$work/t/Packages.real"
{
  cat "$work/t/Packages.real"
  printf '\nPackage: hodeishield\nVersion: 9.9.9-1\nArchitecture: amd64\n'
  printf 'Filename: pool/main/h/hodeishield/hodeishield_9.9.9-1_amd64.deb\nSize: %s\nSHA256: %s\n' \
    "$(wc -c < "$evil_deb" | tr -d ' ')" "$(sha256sum < "$evil_deb" | cut -d' ' -f1)"
} > "$work/t/Packages.evil"
evil_hash=$(sha256sum < "$work/t/Packages.evil" | cut -d' ' -f1)
evil_size=$(wc -c < "$work/t/Packages.evil" | tr -d ' ')
awk -v old="$real_hash" -v new="$evil_hash" -v size="$evil_size" \
  '$1 == old && $3 == "main/binary-amd64/Packages" { print " " new " " size " " $3; next } { print }' \
  "$work/t/Release" > "$work/t/Release.evil"
tool sh /w/bin/evilsign.sh /w/t/Release.evil /w/t/InRelease.evil
endgroup

H=apt/pool/main/h/hodeishield
IR=apt/dists/stable/InRelease
BH=apt/dists/stable/main/binary-amd64/by-hash/SHA256

# fresh <id>: a copy of the base to plant things in.
fresh() { clone "$base" "rt-$1"; }

# Things in the pool that are not the package the signed index vouches for.
fresh b01
put rt-b01 apt/pool/main/o/openssh-server/openssh-server_99.0.0-1_amd64.deb "$ssh_deb"
must_refuse B01 "deb of another package, outside the expected path" rt-b01 "build.sh: unexpected files in the bucket"

fresh b02
put rt-b02 "$H/hodeishield_9.9.9-1_amd64.deb" "$evil_deb"
must_refuse B02 "planted hodeishield deb, not in the signed index" rt-b02 "build.sh: .* is in the bucket but neither in the signed index"

fresh b03
put rt-b03 "$H/hodeishield_9.9.9-1_amd64.deb" "$ssh_deb"
must_refuse B03 "other package's deb renamed hodeishield_9.9.9" rt-b03 "build.sh: .* is in the bucket but neither in the signed index"

fresh b04
put rt-b04 "$H/hodeishield_0.2.1-1_amd64.deb" "$evil_deb"
must_refuse B04 "published deb overwritten with another payload" rt-b04 "build.sh: .* is in the bucket but neither in the signed index"

fresh b05
printf 'not a package\n' > "$work/t/README"
put rt-b05 "$H/README" "$work/t/README"
must_refuse B05 "stray file in the pool" rt-b05 "build.sh: unexpected files in the bucket"

fresh b06
put rt-b06 "$H/sub/hodeishield_9.9.9-1_amd64.deb" "$evil_deb"
must_refuse B06 "deb in a subdirectory of the pool" rt-b06 "build.sh: unexpected files in the bucket"

fresh b07
put rt-b07 "$H/hodeishield_9 9_amd64.deb" "$evil_deb"
put rt-b07 "$H/-hodeishield_9.9_amd64.deb" "$evil_deb"
must_refuse B07 "deb file names with a space or a leading dash" rt-b07 "build.sh: unexpected files in the bucket"

# Things among the RPMs.
fresh b08
put rt-b08 rpm/x86_64/hodeishield-9.9.9-1.x86_64.rpm "$pk/evil/hodeishield-9.9.9-1.x86_64.rpm"
must_refuse B08 "unsigned rpm" rt-b08 "build.sh: .* is not signed with the repository key"

fresh b09
put rt-b09 rpm/x86_64/hodeishield-9.9.9-1.x86_64.rpm "$work/other/hodeishield-9.9.9-1.x86_64.rpm"
must_refuse B09 "rpm signed by another key" rt-b09 "build.sh: .* is not signed with the repository key"

fresh b10
put rt-b10 "rpm/x86_64/$ssh_rpm" "$work/ours/$ssh_rpm"
must_refuse B10 "rpm of another package signed with our key" rt-b10 "build.sh: unexpected files in the bucket"

fresh b11
put rt-b11 rpm/x86_64/hodeishield-99.0.0-1.x86_64.rpm "$work/ours/$ssh_rpm"
must_refuse B11 "our-key rpm named hodeishield with another package inside" rt-b11 \
  "build.sh: .* is not the hodeishield package for x86_64"

fresh b12
put rt-b12 rpm/aarch64/hodeishield-0.2.0-1.aarch64.rpm "$work/ours/hodeishield-0.2.0-1.x86_64.rpm"
must_refuse B12 "our-key x86_64 rpm under an aarch64 name" rt-b12 "build.sh: .* is not the hodeishield package for aarch64"

fresh b13
put rt-b13 rpm/x86_64/hodeishield-0.2.5-1.x86_64.rpm "$work/ours/hodeishield-0.2.0-1.x86_64.rpm"
must_refuse B13 "our-key rpm renamed to another version" rt-b13 "build.sh: .* is not the hodeishield package for x86_64"

fresh b14
put rt-b14 rpm/noarch/hodeishield-0.2.0-1.noarch.rpm "$work/ours/hodeishield-0.2.0-1.x86_64.rpm"
must_refuse B14 "rpm in an unexpected architecture directory" rt-b14 "build.sh: unexpected files in the bucket"

fresh b15
put rt-b15 "rpm/x86_64/x digests signatures OK.rpm" "$pk/evil/hodeishield-9.9.9-1.x86_64.rpm"
must_refuse B15 "rpm whose file name imitates rpm's verdict" rt-b15 "build.sh: unexpected files in the bucket"

# The signed index.
fresh b16
put rt-b16 "$BH/$real_hash" "$work/t/Packages.evil"
put rt-b16 "$H/hodeishield_9.9.9-1_amd64.deb" "$evil_deb"
must_refuse B16 "tampered by-hash Packages and a planted deb" rt-b16 \
  "build.sh: the published Packages \(amd64\) does not match the published InRelease"

fresh b17
sed 's/^Codename: stable$/Codename: stablf/' "$work/t/InRelease" > "$work/t/InRelease.edit"
put rt-b17 "$IR" "$work/t/InRelease.edit"
must_refuse B17 "InRelease edited after signing" rt-b17 "build.sh: the published InRelease does not verify"

fresh b18
cat "$work/t/InRelease" "$work/t/InRelease" > "$work/t/InRelease.two"
put rt-b18 "$IR" "$work/t/InRelease.two"
must_refuse B18 "InRelease with two signed blocks" rt-b18 \
  "(build|publish).sh: the published InRelease (is not a single signed message|does not give one SHA256)"

fresh b19
{ printf 'text before the signed message\n'; cat "$work/t/InRelease"; } > "$work/t/InRelease.before"
put rt-b19 "$IR" "$work/t/InRelease.before"
must_refuse B19 "InRelease with text before the signed message" rt-b19 \
  "build.sh: the published InRelease is not a single signed message"

fresh b20
{ cat "$work/t/InRelease"; printf 'text after the signed message\n'; } > "$work/t/InRelease.after"
put rt-b20 "$IR" "$work/t/InRelease.after"
must_refuse B20 "InRelease with text after the signed message" rt-b20 \
  "build.sh: the published InRelease is not a single signed message"

fresh b21
put rt-b21 "$IR" "$work/t/InRelease.evil"
put rt-b21 "$BH/$evil_hash" "$work/t/Packages.evil"
put rt-b21 "$H/hodeishield_9.9.9-1_amd64.deb" "$evil_deb"
must_refuse B21 "InRelease re-signed with another key, with its Packages and deb" rt-b21 \
  "build.sh: the published InRelease does not verify"

fresh b22
del rt-b22 "$IR"
must_refuse B22 "InRelease removed while the pool is not empty" rt-b22 \
  "build.sh: .* is in the bucket but neither in the signed index"

fresh b23
put rt-b23 "$IR" "$work/t/InRelease.old"
must_refuse B23 "an older InRelease, validly signed" rt-b23 \
  "build.sh: .* is in the bucket but neither in the signed index"

fresh b24
put rt-b24 "$IR" "$work/policy.json"
must_refuse B24 "InRelease replaced by a file that is not signed" rt-b24 \
  "publish.sh: the published InRelease does not give one SHA256"

fresh b25
del rt-b25 "$H/hodeishield_0.2.0-1_amd64.deb"
must_refuse B25 "a deb that the signed index lists is gone" rt-b25 "build.sh: the signed index lists .*, which is not in the bucket"

# The release itself.
fresh n01
must_refuse N01 "release holds a deb of another package" rt-n01 "build.sh: not a hodeishield package file" "$pk/ssh"

fresh n02
mkdir -p "$work/n02"
cp "$ssh_deb" "$work/n02/hodeishield_0.2.2-1_amd64.deb"
must_refuse N02 "release holds another package's deb named hodeishield" rt-n02 \
  "build.sh: .* is not the hodeishield package" "$work/n02"

fresh n03
mkdir -p "$work/n03"
cp "$pk/ssh/$ssh_rpm" "$work/n03/hodeishield-0.2.2-1.x86_64.rpm"
must_refuse N03 "release holds another package's rpm named hodeishield" rt-n03 \
  "build.sh: .* is not the hodeishield package for its architecture" "$work/n03"

fresh n04
mkdir -p "$work/n04"
cp "$pk/alt/hodeishield_0.2.1-1_amd64.deb" "$work/n04/"
must_refuse N04 "same deb file name as a published one, other content" rt-n04 \
  "build.sh: .* is already published with different content" "$work/n04"

fresh n05
mkdir -p "$work/n05"
cp "$pk/alt/hodeishield-0.2.1-1.x86_64.rpm" "$work/n05/"
must_refuse N05 "same rpm file name as a published one, other content" rt-n05 \
  "build.sh: .* is already published with different content" "$work/n05"

# The user of the bucket cannot delete, as in production.
rc=0
mcx rm --quiet "u/rt-ctl/gpg.key" > /dev/null 2>&1 || rc=$?
if [ "$rc" != 0 ] && mcx stat "r/rt-ctl/gpg.key" > /dev/null 2>&1; then
  record "S1 the publishing user cannot delete" "delete denied" "denied" PASS
else
  record "S1 the publishing user cannot delete" "delete denied" "ALLOWED" FAIL
fi

# --- Clients must refuse -----------------------------------------------------------------------------------
# Tampered copies of the published repository (rt-v2), served as they are.
sig='BADSIG|signature verification failed|is not signed'
fresh c1
sed 's/^Codename: stable$/Codename: stablf/' "$work/t/InRelease" > "$work/t/InRelease.c1"
put rt-c1 "$IR" "$work/t/InRelease.c1"
client apt C1 "apt: InRelease tampered" "update and install refused" refuse index "$srv/rt-c1" "$sig"

fresh c2
del rt-c2 "$IR"
sed 's/^Codename: stable$/Codename: stablf/' "$work/t/Release" > "$work/t/Release.c2"
put rt-c2 apt/dists/stable/Release "$work/t/Release.c2"
client apt C2 "apt: Release tampered (no InRelease)" "update and install refused" refuse index "$srv/rt-c2" "$sig"

fresh c3
get rt-v2 rpm/x86_64/repodata/repomd.xml "$work/t/repomd.xml"
sed 's#<revision>#<revision>9#' "$work/t/repomd.xml" > "$work/t/repomd.xml.c3"
cmp -s "$work/t/repomd.xml" "$work/t/repomd.xml.c3" && {
  echo "repo-test.sh: repomd.xml has no <revision>" >&2
  exit 1
}
put rt-c3 rpm/x86_64/repodata/repomd.xml "$work/t/repomd.xml.c3"
client dnf C3 "dnf: repomd.xml tampered" "metadata and install refused" refuse index "$srv/rt-c3" 'Bad GPG signature'

# flip <file>: the same file with one byte changed.
flip() {
  cp "$1" "$2"
  printf 'X' | dd of="$2" bs=1 seek=200 conv=notrunc 2> /dev/null
}

fresh c4
get rt-v2 "$H/hodeishield_0.2.1-1_amd64.deb" "$work/t/c4.deb"
flip "$work/t/c4.deb" "$work/t/c4.bad.deb"
cmp -s "$work/t/c4.deb" "$work/t/c4.bad.deb" && exit 1
put rt-c4 "$H/hodeishield_0.2.1-1_amd64.deb" "$work/t/c4.bad.deb"
client apt C4 "apt: corrupt deb (one byte changed)" "install refused" refuse package "$srv/rt-c4" 'Hash Sum mismatch|unexpected size'

fresh c5
get rt-v2 rpm/x86_64/hodeishield-0.2.1-1.x86_64.rpm "$work/t/c5.rpm"
flip "$work/t/c5.rpm" "$work/t/c5.bad.rpm"
cmp -s "$work/t/c5.rpm" "$work/t/c5.bad.rpm" && exit 1
put rt-c5 rpm/x86_64/hodeishield-0.2.1-1.x86_64.rpm "$work/t/c5.bad.rpm"
client dnf C5 "dnf: corrupt rpm (one byte changed)" "install refused" refuse package "$srv/rt-c5" "checksum doesn't match|Cannot download"

# A repository whose metadata is signed with the repository key but whose only package is not.
for pair in c6:pk/v2 c7:other; do
  id=${pair%%:*} dir=${pair##*:}
  mkdir -p "$work/$id/x86_64"
  cp "$work/$dir/hodeishield-0.2.1-1.x86_64.rpm" "$work/$id/x86_64/"
  tool sh /w/bin/rpmrepo.sh "/w/$id/x86_64"
  fresh "$id"
  mcx rm --recursive --force "r/rt-$id/rpm/x86_64" > /dev/null
  mcx mirror --quiet "/w/$id/x86_64" "r/rt-$id/rpm/x86_64" > /dev/null
done
client dnf C6 "dnf: unsigned rpm, gpgcheck=1" "install refused" refuse package "$srv/rt-c6" \
  'is not signed|GPG check FAILED'
client dnf C7 "dnf: rpm signed by another key, gpgcheck=1" "install refused" refuse package "$srv/rt-c7" \
  'Public key for .* is not installed|GPG check FAILED'
