FROM golang:1.24-alpine AS builder

ARG DEX_VERSION=v2.39.1

# Install build dependencies
RUN apk --no-cache add git curl make gcc musl-dev

# Create workspace
WORKDIR /workspace

# Clone Dex at the specified version
RUN git clone --depth=1 --branch=${DEX_VERSION} https://github.com/dexidp/dex.git

# Create SSH connector directory
RUN mkdir -p dex/connector/ssh

# Copy SSH connector with Dex-compatible interface
COPY docker/dex/ssh.go dex/connector/ssh/ssh.go

# Add SSH connector import to Dex
RUN cd dex && \
    sed -i '/\"github.com\/dexidp\/dex\/connector\/oidc\"/a\\t\"github.com/dexidp/dex/connector/ssh\"' server/server.go && \
    sed -i '/\"oidc\":[[:space:]]*func()/a\\t\"ssh\":            func() ConnectorConfig { return new(ssh.Config) },' server/server.go

# Build Dex with SSH connector
RUN cd dex && \
    go mod tidy && \
    CGO_ENABLED=1 make build

# Runtime image
FROM alpine:3.19

# Install CA certificates for HTTPS connections
RUN apk --no-cache add ca-certificates

# Create non-root user
RUN addgroup -g 1001 dex && \
    adduser -D -u 1001 -G dex dex

# Copy Dex binary
COPY --from=builder /workspace/dex/bin/dex /usr/local/bin/dex

# Set permissions
RUN chown dex:dex /usr/local/bin/dex

# Switch to non-root user
USER dex

# Default command
ENTRYPOINT ["dex"]
CMD ["serve", "/etc/dex/cfg/config.yaml"]