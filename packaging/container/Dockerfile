# The HodeiShield CLI image. It contains only the release's own, already verified binary (see
# .github/workflows/container-image.yml), never one built here, on a base image with CA
# certificates and nothing else: no shell and no package manager.
#
# Build context: a directory holding amd64/hodeishield and arm64/hodeishield, the binaries from the
# release's x86_64 and aarch64 musl archives, plus LICENSE and NOTICE.
#
# The base is gcr.io/distroless/static-debian12:nonroot, pinned by the digest of its multi-arch
# index (dependabot proposes newer digests). It ships /etc/ssl/certs/ca-certificates.crt, which the
# CLI reads as the operating system's trust store, and runs as uid/gid 65532.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

ARG TARGETARCH

COPY --chmod=0555 ${TARGETARCH}/hodeishield /usr/local/bin/hodeishield
COPY LICENSE NOTICE /licenses/

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/hodeishield"]
