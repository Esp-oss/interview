#
# Multi-stage, multi-target build.  Targets:
#
#   --target server   the API       (final image: scratch, ~6 MB)
#   --target client   the CLI       (final image: scratch, ~6 MB)
#
# Design notes that matter for review:
#
#  * The runtime images are `scratch`.  Both binaries are statically linked
#    (CGO_ENABLED=0), so no libc, no shell, no package manager, no userland and
#    therefore no shell-based attack surface and almost no CVE surface.
#  * There is no curl/wget inside `scratch`, so the container health probe is the
#    binary's own `healthcheck` subcommand.  That is not a workaround, it is the
#    point: the probe runs the same code (and the same HTTP server) the service
#    serves, and it needs nothing but the binary itself.
#  * Dependencies are vendored and the build runs with GOPROXY=off, so the image
#    builds without contacting any Go module proxy.  Only the Go base image is
#    pulled from a registry.
#  * The Go toolchain image is the ONLY external dependency of the build. Its tag
#    is a build argument, so a mirror or a pinned digest can be substituted
#    without touching the file:
#        docker compose build --build-arg GO_IMAGE=<registry>/golang:1.26-alpine
#        GO_IMAGE=<registry>/golang:1.26-alpine docker compose up --build
#    Source, modules (vendor/) and rules are all inside this repository.
#  * One platform, deliberately: the build target and the run target are the same
#    machine. A cross-compilation matrix would only add build surface here.
ARG GO_IMAGE=golang:1.26-alpine

FROM ${GO_IMAGE} AS build

WORKDIR /src

ENV CGO_ENABLED=0 \
    GOFLAGS=-mod=vendor \
    GOPROXY=off \
    GOTOOLCHAIN=local

# Dependency layer first: it is only invalidated when go.mod/go.sum/vendor change.
COPY go.mod go.sum ./
COPY vendor/ ./vendor/

COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY rules/ ./rules/

ARG VERSION=dev

# Static binaries: no libc, no dynamic loader, nothing for the scratch runtime to
# satisfy. Build host and run host are the same platform here on purpose - a
# cross-compilation matrix would add buildsurface without changing behaviour.
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false \
        -ldflags="-s -w -X main.version=${VERSION}" \
        -o /out/server ./cmd/server \
 && CGO_ENABLED=0 go build -trimpath -buildvcs=false \
        -ldflags="-s -w -X main.version=${VERSION}" \
        -o /out/client ./cmd/client

# ---------------------------------------------------------------------------
# Runtime: API
# ---------------------------------------------------------------------------
FROM scratch AS server

ARG VERSION=dev
LABEL org.opencontainers.image.title="banner-fingerprint-server" \
      org.opencontainers.image.description="Banner fingerprinting API (static Go binary, scratch runtime)" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="MIT"

COPY --from=build /out/server /server

# Numeric UID with no matching passwd entry: the process needs no home, no shell
# and no supplementary groups.  compose additionally pins user 10001:10001.
USER 10001:10001

EXPOSE 8080

ENTRYPOINT ["/server"]
CMD ["serve"]

# ---------------------------------------------------------------------------
# Runtime: CLI
# ---------------------------------------------------------------------------
FROM scratch AS client

ARG VERSION=dev
LABEL org.opencontainers.image.title="banner-fingerprint-client" \
      org.opencontainers.image.description="Banner fingerprinting CLI (static Go binary, scratch runtime)" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="MIT"

COPY --from=build /out/client /client

USER 10001:10001

ENTRYPOINT ["/client"]
CMD ["-file", "/data/input.json"]
