package ssh

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/dexidp/dex/connector"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/ssh"
)

// Config holds the configuration for the SSH connector.
type Config struct {
	// AuthorizedKeys maps SSH key fingerprints to user information
	AuthorizedKeys map[string]UserInfo `json:"authorized_keys"`

	// AllowedIssuers specifies which JWT issuers are accepted
	AllowedIssuers []string `json:"allowed_issuers"`

	// DefaultGroups are assigned to all authenticated users
	DefaultGroups []string `json:"default_groups"`

	// TokenTTL specifies how long tokens are valid (in seconds)
	TokenTTL int `json:"token_ttl"`
}

// UserInfo contains user identity information.
type UserInfo struct {
	Username string   `json:"username"`
	Email    string   `json:"email"`
	Groups   []string `json:"groups"`
	FullName string   `json:"full_name"`
}

// SSHConnector implements the Dex connector interface for SSH key authentication.
type SSHConnector struct {
	config Config
}

// SSHSignedJWT represents a JWT signed with SSH key (matches client format).
type SSHSignedJWT struct {
	Token     string `json:"token"`
	Signature string `json:"signature"`
	Format    string `json:"format"`
}

// SSHJWTClaims represents JWT claims for SSH authentication.
type SSHJWTClaims struct {
	jwt.RegisteredClaims
	KeyFingerprint string `json:"key_fingerprint"`
	KeyComment     string `json:"key_comment,omitempty"`
	PublicKey      string `json:"public_key"`
}

// Open creates a new SSH connector.
func (c *Config) Open(id string, logger interface{}) (connector.Connector, error) {
	return &SSHConnector{
		config: *c,
	}, nil
}

// LoginURL returns the URL for SSH-based login.
func (c *SSHConnector) LoginURL(scopes connector.Scopes, callbackURL, state string) (string, error) {
	// For SSH authentication, we don't use a traditional login URL
	// Instead, clients directly present SSH-signed JWTs
	return fmt.Sprintf("%s?state=%s&ssh_auth=true", callbackURL, state), nil
}

// HandleCallback processes the SSH authentication callback.
func (c *SSHConnector) HandleCallback(scopes connector.Scopes, r *http.Request) (identity connector.Identity, err error) {
	// Get the SSH JWT from the request
	sshJWT := r.FormValue("ssh_jwt")
	if sshJWT == "" {
		return identity, errors.New("no SSH JWT provided")
	}

	// Validate and extract identity
	return c.validateSSHJWT(sshJWT)
}

// validateSSHJWT validates an SSH-signed JWT and extracts user identity.
func (c *SSHConnector) validateSSHJWT(sshJWTString string) (connector.Identity, error) {
	// Decode the base64-encoded SSH JWT
	sshJWTBytes, err := base64.StdEncoding.DecodeString(sshJWTString)
	if err != nil {
		return connector.Identity{}, fmt.Errorf("failed to decode SSH JWT: %w", err)
	}

	// Parse the SSH-signed JWT structure
	var sshJWT SSHSignedJWT
	parseErr := json.Unmarshal(sshJWTBytes, &sshJWT)
	if parseErr != nil {
		return connector.Identity{}, fmt.Errorf("failed to parse SSH JWT: %w", parseErr)
	}

	// Parse the JWT token (without verification first)
	token, err := jwt.ParseWithClaims(sshJWT.Token, &SSHJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// We'll verify the signature separately using SSH key
		return jwt.UnsafeAllowNoneSignatureType, nil
	})
	if err != nil {
		return connector.Identity{}, fmt.Errorf("failed to parse JWT: %w", err)
	}

	claims, ok := token.Claims.(*SSHJWTClaims)
	if !ok {
		return connector.Identity{}, errors.New("invalid JWT claims")
	}

	// Validate issuer
	if !c.isAllowedIssuer(claims.Issuer) {
		return connector.Identity{}, fmt.Errorf("invalid issuer: %s", claims.Issuer)
	}

	// Validate expiration
	if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
		return connector.Identity{}, errors.New("token has expired")
	}

	// Verify SSH signature
	verifyErr := c.verifySSHSignature(sshJWT.Token, sshJWT.Signature, sshJWT.Format, claims.PublicKey)
	if verifyErr != nil {
		return connector.Identity{}, fmt.Errorf("SSH signature verification failed: %w", verifyErr)
	}

	// Look up user info by SSH key fingerprint
	userInfo, exists := c.config.AuthorizedKeys[claims.KeyFingerprint]
	if !exists {
		return connector.Identity{}, fmt.Errorf("SSH key not authorized: %s", claims.KeyFingerprint)
	}

	// Build identity
	identity := connector.Identity{
		UserID:        userInfo.Username,
		Username:      userInfo.Username,
		Email:         userInfo.Email,
		EmailVerified: true,
		Groups:        append(userInfo.Groups, c.config.DefaultGroups...),
	}

	// Note: PreferredUsername field may not be available in all versions of dex connector
	// Setting display name would go here if the field exists in the connector.Identity struct

	return identity, nil
}

// verifySSHSignature verifies the SSH signature on the JWT.
func (c *SSHConnector) verifySSHSignature(token, signatureB64, format, publicKeyB64 string) error {
	// Decode public key
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return fmt.Errorf("failed to decode public key: %w", err)
	}

	publicKey, err := ssh.ParsePublicKey(publicKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	// Decode signature
	signatureBytes, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	// Create SSH signature structure
	signature := &ssh.Signature{
		Format: format,
		Blob:   signatureBytes,
	}

	// Verify signature
	data := []byte(token)
	verifyErr := publicKey.Verify(data, signature)
	if verifyErr != nil {
		return fmt.Errorf("signature verification failed: %w", verifyErr)
	}

	return nil
}

// isAllowedIssuer checks if the JWT issuer is allowed.
func (c *SSHConnector) isAllowedIssuer(issuer string) bool {
	if len(c.config.AllowedIssuers) == 0 {
		return true // Allow all if none specified
	}

	for _, allowed := range c.config.AllowedIssuers {
		if issuer == allowed {
			return true
		}
	}

	return false
}

// TokenURL returns the token endpoint URL for this connector.
func (c *SSHConnector) TokenURL() string {
	return "/ssh/token"
}

// HandleTokenRequest processes SSH JWT token requests.
func (c *SSHConnector) HandleTokenRequest(w http.ResponseWriter, r *http.Request) {
	// Parse form data
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	// Check grant type
	grantType := r.FormValue("grant_type")
	if grantType != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		http.Error(w, "Unsupported grant type", http.StatusBadRequest)
		return
	}

	// Get SSH JWT assertion
	assertion := r.FormValue("assertion")
	if assertion == "" {
		http.Error(w, "Missing assertion parameter", http.StatusBadRequest)
		return
	}

	// Validate SSH JWT and get identity
	identity, err := c.validateSSHJWT(assertion)
	if err != nil {
		http.Error(w, fmt.Sprintf("Authentication failed: %v", err), http.StatusUnauthorized)
		return
	}

	// Generate access token (this would typically involve calling Dex's token generation)
	accessToken, err := c.generateAccessToken(identity)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Return token response
	tokenResp := map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   c.config.TokenTTL,
	}

	w.Header().Set("Content-Type", "application/json")
	encodeErr := json.NewEncoder(w).Encode(tokenResp)
	if encodeErr != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// generateAccessToken generates an access token for the authenticated user.
func (c *SSHConnector) generateAccessToken(identity connector.Identity) (string, error) {
	// Create claims for the access token
	claims := jwt.MapClaims{
		"iss":    "dex-ssh-connector",
		"sub":    identity.UserID,
		"aud":    "kubernetes",
		"exp":    time.Now().Add(time.Duration(c.config.TokenTTL) * time.Second).Unix(),
		"iat":    time.Now().Unix(),
		"email":  identity.Email,
		"groups": identity.Groups,
		"name":   identity.Username,
	}

	// Sign token (in practice, use Dex's signing key)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// This is a placeholder - in real implementation, use Dex's internal signing mechanisms
	secretKey := []byte("your-secret-key") // Should come from Dex configuration
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
