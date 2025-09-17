FROM golang:1.25-alpine AS builder

ARG DEX_VERSION=v2.39.1
ARG KUBECTL_SSH_OIDC_VERSION=main

# Install build dependencies
RUN apk --no-cache add git curl make gcc musl-dev

# Create workspace
WORKDIR /workspace

# Clone Dex at the specified version
RUN git clone --depth=1 --branch=${DEX_VERSION} https://github.com/dexidp/dex.git

# Clone kubectl-ssh-oidc at the specified version (cache-busted)
# Add CACHE_BUST argument to force fresh git clone on each build
ARG CACHE_BUST=1
RUN echo "Cache bust: ${CACHE_BUST}" && git clone --depth=1 --branch=${KUBECTL_SSH_OIDC_VERSION} https://github.com/nikogura/kubectl-ssh-oidc.git

# Create SSH connector directory
RUN mkdir -p dex/connector/ssh

# Copy SSH connector from kubectl-ssh-oidc repository
RUN cp kubectl-ssh-oidc/pkg/ssh/ssh.go dex/connector/ssh/ssh.go && \
    cp kubectl-ssh-oidc/pkg/ssh/version.go dex/connector/ssh/version.go

# SSH connector already uses slog.Logger in source code - no patches needed

# Add SSH connector import to Dex and custom endpoint routing
RUN cd dex && \
    sed -i '/\"github.com\/dexidp\/dex\/connector\/oidc\"/a\\t\"github.com/dexidp/dex/connector/ssh\"' server/server.go && \
    sed -i '/\"oidc\":[[:space:]]*func()/a\\t\"ssh\":            func() ConnectorConfig { return new(ssh.Config) },' server/server.go

# Add SSH direct token endpoint routes
RUN cd dex && \
    sed -i '/handleFunc.*\/callback.*handleConnectorCallback/a\\thandleFunc("/auth/ssh/token", s.handleSSHDirectToken)' server/server.go && \
    sed -i '/handleFunc.*\/auth\/ssh\/token/a\\thandleFunc("/auth/ssh", s.handleSSHDirectToken)' server/server.go

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

	// Provide Dex's signing key to the SSH connector
	if sshConn, ok := conn.Connector.(interface{
		HandleDirectTokenRequest(http.ResponseWriter, *http.Request)
		SetSigningKeyFromInterface(interface{}) error
	}); ok {
		// Get Dex's current signing key
		keySet, keySetErr := s.storage.GetKeys()
		if keySetErr != nil {
			s.logger.Errorf("Failed to get signing keys: %v", keySetErr)
			http.Error(w, "Failed to get signing keys", http.StatusInternalServerError)
			return
		}

		// DEBUG: Log all available keys to understand Dex's key structure
		s.logger.Infof("DEBUG: Dex keySet.SigningKey type: %T", keySet.SigningKey)
		s.logger.Infof("DEBUG: Dex SigningKey ID: %s", keySet.SigningKey.KeyID)
		s.logger.Infof("DEBUG: Dex has %d verification keys", len(keySet.VerificationKeys))
		for i, vk := range keySet.VerificationKeys {
			s.logger.Infof("DEBUG: VerificationKey[%d] KeyID: %s, type: %T", i, vk.PublicKey.KeyID, vk.PublicKey)
		}

		// Provide ALL available keys to the SSH connector so it can try each one
		// First add the current signing key
		signingKey := keySet.SigningKey
		s.logger.Infof("DEBUG: Adding Dex SigningKey with KeyID: %s", signingKey.KeyID)

		if keyErr := sshConn.SetSigningKeyFromInterface(signingKey); keyErr != nil {
			s.logger.Errorf("Failed to set signing key: %v", keyErr)
			http.Error(w, "Failed to configure signing key", http.StatusInternalServerError)
			return
		}

		// Try to add verification keys if they contain private key material
		// This might work if Dex stores private keys in verification keys for rotation
		for i, vk := range keySet.VerificationKeys {
			s.logger.Infof("DEBUG: Attempting to add VerificationKey[%d] with KeyID: %s", i, vk.PublicKey.KeyID)

			// Try to add the verification key - if it has private material, great!
			// If not, SetSigningKeyFromInterface will log and skip it
			if addErr := sshConn.SetSigningKeyFromInterface(vk.PublicKey); addErr != nil {
				s.logger.Infof("DEBUG: VerificationKey[%d] cannot be used for signing: %v", i, addErr)
			} else {
				s.logger.Infof("DEBUG: Successfully added VerificationKey[%d] with KeyID: %s", i, vk.PublicKey.KeyID)
			}
		}

		s.logger.Infof("DEBUG: SSH connector initialized with signing key options")

		sshConn.HandleDirectTokenRequest(w, r)
	} else {
		s.logger.Errorf("SSH connector doesn't implement HandleDirectTokenRequest")
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
    cd ../kubectl-ssh-oidc && \
    GIT_VERSION=$(git describe --tags --always 2>/dev/null || echo "${KUBECTL_SSH_OIDC_VERSION}") && \
    cd ../dex && \
    LDFLAGS="-X github.com/dexidp/dex/connector/ssh.Version=${GIT_VERSION}" && \
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