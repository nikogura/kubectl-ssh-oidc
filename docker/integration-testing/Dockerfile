FROM golang:1.25-alpine AS builder

ARG DEX_VERSION=v2.44.0

# Install build dependencies
RUN apk --no-cache add git curl make gcc musl-dev

# Create workspace
WORKDIR /workspace

# Clone Dex at the specified version
RUN git clone --depth=1 --branch=${DEX_VERSION} https://github.com/dexidp/dex.git

# Create SSH connector directory
RUN mkdir -p dex/connector/ssh

# Copy SSH connector from project source
COPY pkg/ssh/ssh.go dex/connector/ssh/ssh.go
COPY pkg/ssh/version.go dex/connector/ssh/version.go

# SSH connector uses slog.Logger compatible with latest Dex

# Add SSH connector import to Dex and custom endpoint routing
RUN cd dex && \
    sed -i '/\"github.com\/dexidp\/dex\/connector\/oidc\"/a\\t\"github.com/dexidp/dex/connector/ssh\"' server/server.go && \
    sed -i '/\"oidc\":[[:space:]]*func()/a\\t\"ssh\":            func() ConnectorConfig { return new(ssh.Config) },' server/server.go

# Add SSH direct token endpoint route
RUN cd dex && \
    sed -i '/handleFunc.*\/callback.*handleConnectorCallback/a\\thandleFunc("/auth/ssh/token", s.handleSSHDirectToken)' server/server.go

# Add SSH direct token handler method with slog.Logger compatibility
RUN cd dex && \
    cat >> server/server.go << 'EOF'

func (s *Server) handleSSHDirectToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	conn, err := s.getConnector(r.Context(), "ssh")
	if err != nil {
		s.logger.Error("Failed to get SSH connector", "error", err)
		http.Error(w, "SSH connector not available", http.StatusServiceUnavailable)
		return
	}

	// Provide Dex's signing key to the SSH connector
	if sshConn, ok := conn.Connector.(interface{
		HandleDirectTokenRequest(http.ResponseWriter, *http.Request)
		SetSigningKeyFromInterface(interface{}) error
	}); ok {
		// Get Dex's current signing key
		keySet, keySetErr := s.storage.GetKeys(r.Context())
		if keySetErr != nil {
			s.logger.Error("Failed to get signing keys", "error", keySetErr)
			http.Error(w, "Failed to get signing keys", http.StatusInternalServerError)
			return
		}

		// DEBUG: Log all available keys to understand Dex's key structure
		s.logger.Info("DEBUG: Dex keySet.SigningKey type", "type", fmt.Sprintf("%T", keySet.SigningKey))
		s.logger.Info("DEBUG: Dex SigningKey ID", "keyID", keySet.SigningKey.KeyID)
		s.logger.Info("DEBUG: Dex has verification keys", "count", len(keySet.VerificationKeys))
		for i, vk := range keySet.VerificationKeys {
			s.logger.Info("DEBUG: VerificationKey", "index", i, "keyID", vk.PublicKey.KeyID, "type", fmt.Sprintf("%T", vk.PublicKey))
		}

		// Provide ALL available keys to the SSH connector so it can try each one
		// First add the current signing key
		signingKey := keySet.SigningKey
		s.logger.Info("DEBUG: Adding Dex SigningKey", "keyID", signingKey.KeyID)

		if keyErr := sshConn.SetSigningKeyFromInterface(signingKey); keyErr != nil {
			s.logger.Error("Failed to set signing key", "error", keyErr)
			http.Error(w, "Failed to configure signing key", http.StatusInternalServerError)
			return
		}

		// Try to add verification keys if they contain private key material
		for i, vk := range keySet.VerificationKeys {
			s.logger.Info("DEBUG: Attempting to add VerificationKey", "index", i, "keyID", vk.PublicKey.KeyID)

			if addErr := sshConn.SetSigningKeyFromInterface(vk.PublicKey); addErr != nil {
				s.logger.Info("DEBUG: VerificationKey cannot be used for signing", "index", i, "error", addErr)
			} else {
				s.logger.Info("DEBUG: Successfully added VerificationKey", "index", i, "keyID", vk.PublicKey.KeyID)
			}
		}

		s.logger.Info("DEBUG: SSH connector initialized with signing key options")

		sshConn.HandleDirectTokenRequest(w, r)
	} else {
		s.logger.Error("SSH connector doesn't implement HandleDirectTokenRequest")
		http.Error(w, "SSH direct token not supported", http.StatusNotImplemented)
	}
}
EOF

# Add JOSE dependency for SSH connector (v4 to match Dex v2.43.1)
RUN cd dex && \
    go mod edit -require github.com/go-jose/go-jose/v4@v4.0.1 && \
    go mod tidy

# Build Dex with SSH connector and version injection
RUN cd dex && \
    LDFLAGS="-X github.com/dexidp/dex/connector/ssh.Version=local" && \
    CGO_ENABLED=1 go build -ldflags "${LDFLAGS}" -o bin/dex ./cmd/dex

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