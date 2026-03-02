# ── Stage 1: Build ───────────────────────────────────────────────────────────
FROM golang:1.24-alpine AS builder

ARG VERSION=dev

# Install git for `git describe` in build scripts
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /src

# Cache module downloads separately from source changes
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

# Build both binaries with optimised flags: no CGO, stripped symbols
RUN CGO_ENABLED=0 go build \
      -ldflags "-X main.version=${VERSION} -s -w" \
      -o /out/agentsentry \
      ./cmd/agentsentry/

RUN CGO_ENABLED=0 go build \
      -ldflags "-X main.version=${VERSION} -s -w" \
      -o /out/agentsentry-mcp \
      ./cmd/mcpserver/

# ── Stage 2: Minimal runtime image ───────────────────────────────────────────
FROM scratch

# Copy TLS root certificates (needed for outbound HTTPS in the scanner)
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy timezone data
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy compiled binaries
COPY --from=builder /out/agentsentry     /usr/local/bin/agentsentry
COPY --from=builder /out/agentsentry-mcp /usr/local/bin/agentsentry-mcp

# Default: run the CLI
ENTRYPOINT ["/usr/local/bin/agentsentry"]
CMD ["--help"]

# Metadata labels (OCI standard)
LABEL org.opencontainers.image.title="AgentSafe"
LABEL org.opencontainers.image.description="AI Agent Tool Security Scanner"
LABEL org.opencontainers.image.source="https://github.com/AgentSafe-AI/agentsentry"
LABEL org.opencontainers.image.licenses="MIT"
