#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
#
# Builds the APT and DNF repositories served at packages.hodeishield.com, without any database: the
# repository is whatever is in <repo-dir> (a copy of the bucket's packages) plus the new packages, and
# every index is regenerated and signed from that.
#
#   build.sh <repo-dir> <new-packages-dir> <published-dir>
#
# <published-dir> holds the APT index as currently published, if there is one: InRelease, and for each
# architecture main/binary-<arch>/Packages (the copy that InRelease names by hash).
#
# Environment:
#   GNUPGHOME     a keyring holding the signing subkey (the primary's secret part is not needed)
#   SIGNING_KEY   fingerprint of the signing subkey, with a trailing "!" to force that subkey
#   PUBLIC_KEY    path to the ASCII-armored public key published as /gpg.key
#
# Runs in the pinned image named in packaging/repo/image (apt-ftparchive, createrepo_c, gnupg, rpm).
# A package that is already in the repository is never replaced: same name with different content is
# an error, so a published version cannot change.
#
# The bucket is not trusted: whoever can write to it cannot sign, and must not be able to get anything
# signed. A package from the bucket is indexed only if this key already vouched for it: a .deb must be
# listed, with its size and SHA256, in the Packages that the published InRelease signs, and an .rpm
# must carry this key's signature. The only other packages are the new ones, which the caller has
# verified against the release's SHA256SUMS. Every package must be named hodeishield. Anything else
# is an error, and nothing is signed.

set -eu

repo=$1
new=$2
published=$3
: "${GNUPGHOME:?}" "${SIGNING_KEY:?}" "${PUBLIC_KEY:?}"
here=$(cd "$(dirname "$0")" && pwd)

# rpm and rpmsign get a private database holding only the public key, never the system's.
rpmdb=$(mktemp -d)
check=$(mktemp -d)
trap 'rm -rf "$rpmdb" "$check"' EXIT
rpm --dbpath "$rpmdb" --import "$PUBLIC_KEY"
gpg --batch --quiet --dearmor --output "$check/key.gpg" "$PUBLIC_KEY"

die() {
  printf 'build.sh: %s\n' "$*" >&2
  exit 1
}

# Copies a new package into place, refusing to change a package that is already published.
place() {
  src=$1 dest=$2
  if [ -e "$dest" ]; then
    cmp -s "$src" "$dest" || die "$(basename "$dest") is already published with different content"
    return 1
  fi
  mkdir -p "$(dirname "$dest")"
  cp "$src" "$dest"
}

# Signed with this key. rpm checks against the private database, which holds only this key, and the
# whole verdict is compared: the exit status is 0 for an unsigned package, and the output starts with
# the file name.
rpm_signed() {
  [ "$(rpm --dbpath "$rpmdb" --checksig "$1" 2>&1)" = "$1: digests signatures OK" ]
}

# Named hodeishield, built for <arch>, and in a file named after what it is.
rpm_named() {
  [ "$(rpm --dbpath "$rpmdb" -qp --qf '%{NAME} %{ARCH} %{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}.rpm' "$1" \
    2> /dev/null)" = "hodeishield $2 $(basename "$1")" ]
}

# The file names of the packages, as extended regular expressions (a version holds only what dpkg or
# rpm allow in one).
deb_version='[0-9A-Za-z.+~-]+'
rpm_version='[0-9A-Za-z.+~^_-]+'
deb_name="hodeishield_${deb_version}_(amd64|arm64)\\.deb"
rpm_name="hodeishield-${rpm_version}\\.(x86_64|aarch64)\\.rpm"

# --- The new packages --------------------------------------------------------------------------------
# Verified by the caller; still, only the hodeishield package is ever published.
odd=$(find "$new" -mindepth 1 -maxdepth 1 -regextype posix-extended \( -name '*.deb' -o -name '*.rpm' \) \
  ! \( -type f \( -regex ".*/$deb_name" -o -regex ".*/$rpm_name" \) \) -print)
[ -z "$odd" ] || die "not a hodeishield package file: $odd"
for deb in "$new"/*.deb; do
  [ -e "$deb" ] || continue
  [ "$(dpkg-deb --field "$deb" Package)" = hodeishield ] ||
    die "$(basename "$deb") is not the hodeishield package"
done
for rpm in "$new"/*.rpm; do
  [ -e "$rpm" ] || continue
  arch=${rpm%.rpm}
  rpm_named "$rpm" "${arch##*.}" ||
    die "$(basename "$rpm") is not the hodeishield package for its architecture"
done

# --- The packages from the bucket ----------------------------------------------------------------------
# Only regular files with the names that this script writes, so nothing else reaches the tools below.
odd=$(cd "$repo" && find . -regextype posix-extended ! -type d ! \( -type f \( \
  -regex "\\./apt/pool/main/h/hodeishield/$deb_name" -o \
  -regex "\\./rpm/x86_64/hodeishield-${rpm_version}\\.x86_64\\.rpm" -o \
  -regex "\\./rpm/aarch64/hodeishield-${rpm_version}\\.aarch64\\.rpm" \) \) -print)
[ -z "$odd" ] || die "unexpected files in the bucket: $odd"

# "<Filename> <Size> <SHA256>" of every package that the published, signed APT index lists.
vouched=$check/vouched
: > "$vouched"
if [ -e "$published/InRelease" ]; then
  # A single clear-signed message and nothing around it, and only the signed text is read.
  if ! {
    [ "$(head -n 1 "$published/InRelease")" = '-----BEGIN PGP SIGNED MESSAGE-----' ] &&
      [ "$(tail -n 1 "$published/InRelease")" = '-----END PGP SIGNATURE-----' ] &&
      [ "$(grep -c '^-----BEGIN PGP' "$published/InRelease")" = 2 ] &&
      [ "$(grep -c '^-----END PGP' "$published/InRelease")" = 1 ]
  }; then
    die "the published InRelease is not a single signed message"
  fi
  gpgv --quiet --keyring "$check/key.gpg" --output "$check/Release" "$published/InRelease" 2> /dev/null ||
    die "the published InRelease does not verify"
  for arch in amd64 arm64; do
    packages=$published/main/binary-$arch/Packages
    [ -f "$packages" ] || die "the published Packages ($arch) is missing"
    [ "$(awk -v f="main/binary-$arch/Packages" \
      '/^[^ ]/ { s = ($0 == "SHA256:"); next } s && $3 == f { print $1, $2 }' "$check/Release")" = \
      "$(sha256sum < "$packages" | cut -d' ' -f1) $(stat -c %s "$packages")" ] ||
      die "the published Packages ($arch) does not match the published InRelease"
    awk 'BEGIN { RS = ""; FS = "\n" }
      {
        p = f = s = h = ""
        for (i = 1; i <= NF; i++) {
          if ($i ~ /^Package: /) p = substr($i, 10)
          else if ($i ~ /^Filename: /) f = substr($i, 11)
          else if ($i ~ /^Size: /) s = substr($i, 7)
          else if ($i ~ /^SHA256: /) h = substr($i, 9)
        }
        if (p == "hodeishield") print f, s, h
      }' "$packages" >> "$vouched"
  done
fi
# Every .deb in the bucket is in that index with the same size and SHA256, or is one of the new
# packages (left there by an earlier run of this release that did not finish).
if [ -d "$repo/apt/pool" ]; then
  (cd "$repo/apt" && find pool -type f) | while read -r file; do
    sha256=$(sha256sum < "$repo/apt/$file" | cut -d' ' -f1)
    grep -qxF "$file $(stat -c %s "$repo/apt/$file") $sha256" "$vouched" ||
      cmp -s "$new/$(basename "$file")" "$repo/apt/$file" 2> /dev/null ||
      die "$file is in the bucket but neither in the signed index nor in this release"
  done
fi
# And nothing that index lists has gone missing, so no published package is dropped unnoticed.
while read -r file _; do
  [ -f "$repo/apt/$file" ] || die "the signed index lists $file, which is not in the bucket"
done < "$vouched"
# Every .rpm in the bucket carries this key's signature. With no published index there should be no
# package at all, except the new ones (as above).
for arch in x86_64 aarch64; do
  for rpm in "$repo/rpm/$arch"/*.rpm; do
    [ -e "$rpm" ] || continue
    rpm_signed "$rpm" || die "$(basename "$rpm") in the bucket is not signed with the repository key"
    rpm_named "$rpm" "$arch" ||
      die "$(basename "$rpm") in the bucket is not the hodeishield package for $arch"
    [ -e "$published/InRelease" ] ||
      [ "$(rpm --dbpath "$rpmdb" -qp --qf '%{SHA256HEADER}' "$rpm")" = \
        "$(rpm --dbpath "$rpmdb" -qp --qf '%{SHA256HEADER}' "$new/$(basename "$rpm")" 2> /dev/null)" ] ||
      die "$(basename "$rpm") is in the bucket, which has no signed index, and is not in this release"
  done
done

# --- APT -------------------------------------------------------------------------------------------
pool="$repo/apt/pool/main/h/hodeishield"
for deb in "$new"/*.deb; do
  [ -e "$deb" ] || continue
  place "$deb" "$pool/$(basename "$deb")" || true
done

dists="$repo/apt/dists/stable"
# A previous build's files must not be listed in the new Release.
rm -f "$dists/Release" "$dists/InRelease" "$dists/Release.gpg"
for arch in amd64 arm64; do
  dir="$dists/main/binary-$arch"
  mkdir -p "$dir"
  (cd "$repo/apt" && apt-ftparchive --arch "$arch" packages pool) > "$dir/Packages"
  gzip -9nkf "$dir/Packages"
  xz -9kf "$dir/Packages"
  printf 'Archive: stable\nComponent: main\nOrigin: HodeiShield\nLabel: HodeiShield\nArchitecture: %s\n' \
    "$arch" > "$dir/Release"
done
# DoByHash adds "Acquire-By-Hash: yes" and a copy of every index under by-hash/SHA256/<hash> (and
# SHA512), next to it. The repository is served through a CDN and uploaded file by file, so a client
# can hold an InRelease older than the indexes it sees; with by-hash it asks for the index by the hash
# that its own InRelease lists, which stays in the bucket for good (nothing is ever deleted).
apt-ftparchive \
  -o APT::FTPArchive::DoByHash=true \
  -o APT::FTPArchive::Release::Origin=HodeiShield \
  -o APT::FTPArchive::Release::Label=HodeiShield \
  -o APT::FTPArchive::Release::Suite=stable \
  -o APT::FTPArchive::Release::Codename=stable \
  -o "APT::FTPArchive::Release::Architectures=amd64 arm64" \
  -o APT::FTPArchive::Release::Components=main \
  -o "APT::FTPArchive::Release::Description=HodeiShield CLI packages" \
  release "$dists" > "$repo/Release.tmp"
mv "$repo/Release.tmp" "$dists/Release"
gpg --batch --yes --local-user "$SIGNING_KEY" --digest-algo SHA512 --clearsign \
  --output "$dists/InRelease" "$dists/Release"
gpg --batch --yes --local-user "$SIGNING_KEY" --digest-algo SHA512 --armor --detach-sign \
  --output "$dists/Release.gpg" "$dists/Release"

# --- DNF -------------------------------------------------------------------------------------------
for arch in x86_64 aarch64; do
  dir="$repo/rpm/$arch"
  mkdir -p "$dir"
  for rpm in "$new"/*."$arch".rpm; do
    [ -e "$rpm" ] || continue
    dest="$dir/$(basename "$rpm")"
    if [ -e "$dest" ]; then
      # Signing changes only the signature header, so the main header's digest identifies the
      # package: the same digest is the same package (e.g. a re-run), anything else is an error.
      [ "$(rpm --dbpath "$rpmdb" -qp --qf '%{SHA256HEADER}' "$rpm")" = \
        "$(rpm --dbpath "$rpmdb" -qp --qf '%{SHA256HEADER}' "$dest")" ] ||
        die "$(basename "$rpm") is already published with different content"
      continue
    fi
    cp "$rpm" "$dest"
    # The repository's copy carries an RPM signature, so gpgcheck=1 works; the release asset stays as
    # it was published (signed with Sigstore).
    rpmsign --define "_dbpath $rpmdb" --define "_gpg_name $SIGNING_KEY" --define "_gpg_digest_algo sha512" \
      --addsign "$dest" > /dev/null
  done
  # gzip, not the zstd default: dnf on RHEL/Rocky 8 cannot read zstd metadata.
  createrepo_c --quiet --update --no-database --general-compress-type=gz "$dir"
  rm -f "$dir/repodata/repomd.xml.asc"
  gpg --batch --yes --local-user "$SIGNING_KEY" --digest-algo SHA512 --armor --detach-sign \
    --output "$dir/repodata/repomd.xml.asc" "$dir/repodata/repomd.xml"
done
cp "$here/hodeishield.repo" "$repo/rpm/hodeishield.repo"

# --- Key and landing page --------------------------------------------------------------------------
cp "$PUBLIC_KEY" "$repo/gpg.key"
fingerprint=$(gpg --batch --with-colons --show-keys "$PUBLIC_KEY" | awk -F: '$1 == "fpr" { print $10; exit }')
[ -n "$fingerprint" ] || die "cannot read the fingerprint of $PUBLIC_KEY"
sed "s/@FINGERPRINT@/$fingerprint/g" "$here/index.html" > "$repo/index.html"

# --- Self-check before anything is uploaded ---------------------------------------------------------
gpgv --quiet --keyring "$check/key.gpg" "$dists/InRelease" 2> /dev/null || die "InRelease does not verify"
gpgv --quiet --keyring "$check/key.gpg" "$dists/Release.gpg" "$dists/Release" 2> /dev/null ||
  die "Release.gpg does not verify"
# Every index that Release lists must be there, with its by-hash copies (apt-ftparchive makes none for
# the per-architecture Release files, whose content never changes). apt asks for the strongest hash.
grep -q '^Acquire-By-Hash: yes$' "$dists/Release" || die "Release lacks Acquire-By-Hash"
for algo in SHA256 SHA512; do
  sum=sha${algo#SHA}sum
  sed -n "/^$algo:/,/^[^ ]/p" "$dists/Release" | grep '^ ' | while read -r hash _ file; do
    [ -f "$dists/$file" ] || die "Release lists $file, which is missing"
    [ "$("$sum" < "$dists/$file")" = "$hash  -" ] || die "$file does not match its $algo hash in Release"
    case $file in */Release) continue ;; esac
    byhash="$dists/$(dirname "$file")/by-hash/$algo/$hash"
    [ -f "$byhash" ] || die "$file has no $algo by-hash copy"
    cmp -s "$byhash" "$dists/$file" || die "the $algo by-hash copy of $file differs"
  done
done
for arch in amd64 arm64; do
  grep '^Filename: ' "$dists/main/binary-$arch/Packages" | while read -r _ file; do
    [ -f "$repo/apt/$file" ] || die "Packages ($arch) names $file, which is missing"
  done
  if grep '^Package: ' "$dists/main/binary-$arch/Packages" | grep -qvx 'Package: hodeishield'; then
    die "Packages ($arch) lists a package other than hodeishield"
  fi
done
for arch in x86_64 aarch64; do
  gpgv --quiet --keyring "$check/key.gpg" "$repo/rpm/$arch/repodata/repomd.xml.asc" \
    "$repo/rpm/$arch/repodata/repomd.xml" 2> /dev/null || die "repomd.xml ($arch) does not verify"
  for rpm in "$repo/rpm/$arch"/*.rpm; do
    [ -e "$rpm" ] || continue
    rpm_signed "$rpm" || die "$(basename "$rpm") has no valid signature"
    rpm_named "$rpm" "$arch" || die "$(basename "$rpm") is not the hodeishield package for $arch"
  done
done
printf 'Repository built and verified (key %s).\n' "$fingerprint"
