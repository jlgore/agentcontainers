# Build context is the repo ROOT (needs the whole module):
#   docker build -f test/orchestrator/Dockerfile -t <ref> .
FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/harness-worker ./test/orchestrator

# Distroless static: the worker only needs the binary + CA roots (for the
# in-cluster kube-apiserver TLS). It shells out to nothing — all guest work is
# over the Go SSH client.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/harness-worker /usr/local/bin/harness-worker
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/harness-worker"]
