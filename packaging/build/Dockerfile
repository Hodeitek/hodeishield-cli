# The image the Linux musl binaries are built in (packaging/build/build.sh). Its arguments come from
# packaging/build/image. Debian packages are installed from the pinned snapshot, not from the
# current archive, so the C compiler and the musl headers do not change between builds.
#
# musl-tools provides the musl-gcc / <arch>-linux-musl-gcc wrapper that the `cc` crate needs to
# compile the C sources of aws-lc-sys (rustls uses aws-lc-rs). No cmake or nasm is needed:
# aws-lc-sys ships prebuilt NASM objects and only calls a plain C compiler on these targets.
ARG IMAGE
FROM ${IMAGE}
ARG SNAPSHOT
ARG PACKAGES
ARG TARGET
RUN sed -i \
      -e "s|http://deb.debian.org/debian-security|http://snapshot.debian.org/archive/debian-security/${SNAPSHOT}|" \
      -e "s|http://deb.debian.org/debian\$|http://snapshot.debian.org/archive/debian/${SNAPSHOT}|" \
      /etc/apt/sources.list.d/debian.sources \
 && apt-get -o Acquire::Check-Valid-Until=false update -qq \
 && apt-get install -y -qq --no-install-recommends ${PACKAGES} \
 && rm -rf /var/lib/apt/lists/* \
 && rustup component add rustfmt clippy \
 && rustup target add "${TARGET}"
