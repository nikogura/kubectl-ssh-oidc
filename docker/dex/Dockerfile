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
COPY pkg/ssh/ssh.go dex/connector/ssh/ssh.go

# Patch SSH connector for Dex v2.39.1+ compatibility
RUN cd dex/connector/ssh && \
    sed -i 's|"github.com/dexidp/dex/connector"|"github.com/dexidp/dex/connector"\n\t"github.com/dexidp/dex/pkg/log"|' ssh.go && \
    sed -i 's|func (c \*Config) Open(id string, logger interface{})|func (c *Config) Open(id string, logger log.Logger)|' ssh.go && \
    sed -i 's|logger interface{}|logger log.Logger|' ssh.go

# Add SSH connector import to Dex and custom endpoint routing
RUN cd dex && \
    sed -i '/\"github.com\/dexidp\/dex\/connector\/oidc\"/a\\t\"github.com/dexidp/dex/connector/ssh\"' server/server.go && \
    sed -i '/\"oidc\":[[:space:]]*func()/a\\t\"ssh\":            func() ConnectorConfig { return new(ssh.Config) },' server/server.go

# Add SSH direct token endpoint route
RUN cd dex && \
    sed -i '/handleFunc.*\/callback.*handleConnectorCallback/a\\thandleFunc("/auth/ssh/token", s.handleSSHDirectToken)' server/server.go

# Add SSH direct token handler method
RUN cd dex && \
    cat >> server/server.go << 'EOF'

func (s *Server) handleSSHDirectToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	conn, err := s.getConnector("ssh")
	if err != nil {
		s.logger.Errorf("Failed to get SSH connector: %v", err)
		http.Error(w, "SSH connector not available", http.StatusServiceUnavailable)
		return
	}

	if sshConn, ok := conn.Connector.(interface{ HandleDirectTokenRequest(http.ResponseWriter, *http.Request) }); ok {
		sshConn.HandleDirectTokenRequest(w, r)
	} else {
		s.logger.Errorf("SSH connector doesn't implement HandleDirectTokenRequest")
		http.Error(w, "SSH direct token not supported", http.StatusNotImplemented)
	}
}
EOF

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