# The S3-compatible server and client that repo-test.sh publishes to: MinIO, built from its source at
# the releases below (the project no longer publishes images or binaries). Go fetches the modules
# through the checksum database, so what is built is fixed by the two tags and the Go image.
# MinIO is licensed under the GNU AGPL v3; it is built and run here only as a throwaway test
# service inside CI and is never shipped or distributed with the CLI or its packages.
# Bumped by hand in the periodic dependency review (CONTRIBUTING.md).
ARG BASE
FROM golang:1.24-trixie@sha256:5835f052b784aa39f2fe9070def3568605c8bc3fcd810f10402066348b61e716 AS build
ENV GOBIN=/out CGO_ENABLED=0
RUN go install github.com/minio/minio@RELEASE.2025-09-07T16-13-09Z \
  && go install github.com/minio/mc@RELEASE.2025-08-13T08-35-41Z

FROM ${BASE}
COPY --from=build /out/minio /out/mc /usr/local/bin/
