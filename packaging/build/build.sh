#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
#
# Builds the Linux musl binary of the CLI in the pinned image named in packaging/build/image, the way
# the release does, so that a rebuild from the same tag gives the same bytes (docs/verifying-releases.md,
# "Rebuild the Linux binaries").
#
#   build.sh <target>
#
# <target> is x86_64-unknown-linux-musl or aarch64-unknown-linux-musl, and needs a machine of that
# architecture. Needs docker and network access to crates.io. The binary is written to
# target/build-image/<target>/release/hodeishield in this repository, and its path is the last line
# of the output.
#
# The repository is mounted at /src and Cargo's home is under it, so the paths compiled into the
# binary do not depend on where the repository is on the host.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
target=${1:?usage: build.sh <target>}

case $target in
  x86_64-unknown-linux-musl) platform=linux/amd64 ;;
  aarch64-unknown-linux-musl) platform=linux/arm64 ;;
  *) echo "build.sh: unknown target $target" >&2; exit 2 ;;
esac

# shellcheck source=/dev/null
. "$here/image"

channel=$(sed -n 's/^channel = "\(.*\)"$/\1/p' "$root/rust-toolchain.toml")
case $IMAGE in
  "rust:$channel-"*@sha256:*) ;;
  *) echo "build.sh: the build image $IMAGE is not Rust $channel (rust-toolchain.toml), pinned by digest" >&2; exit 1 ;;
esac

tag="hodeishield-build:$target"
docker build --quiet --platform "$platform" --tag "$tag" \
  --build-arg IMAGE="$IMAGE" --build-arg SNAPSHOT="$SNAPSHOT" --build-arg PACKAGES="$PACKAGES" \
  --build-arg TARGET="$target" - < "$here/Dockerfile" > /dev/null

docker run --rm --platform "$platform" --user "$(id -u):$(id -g)" \
  --volume "$root:/src" --workdir /src \
  --env HOME=/tmp --env CARGO_HOME=/src/target/build-image/cargo-home \
  --env CARGO_TARGET_DIR=/src/target/build-image \
  "$tag" cargo build --release --locked --target "$target" -p hodeishield-cli

echo "$root/target/build-image/$target/release/hodeishield"
