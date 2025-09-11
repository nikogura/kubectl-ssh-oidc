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
	// Users maps usernames to their SSH key configuration and user information
	Users map[string]UserConfig `json:"users"`

	// AuthorizedKeys maps SSH key fingerprints to user information (DEPRECATED: use Users instead)
	// This field is maintained for backward compatibility
	AuthorizedKeys map[string]UserInfo `json:"authorized_keys,omitempty"`

	// AllowedIssuers specifies which JWT issuers are accepted
	AllowedIssuers []string `json:"allowed_issuers"`

	// DefaultGroups are assigned to all authenticated users
	DefaultGroups []string `json:"default_groups"`

	// TokenTTL specifies how long tokens are valid (in seconds)
	TokenTTL int `json:"token_ttl"`
}

// UserConfig contains a user's SSH keys and identity information.
type UserConfig struct {
	// Keys is a list of SSH key fingerprints authorized for this user
	Keys []string `json:"keys"`

	// UserInfo contains the user's identity information
	UserInfo `json:",inline"`
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
// Updated for jwt-ssh-agent approach: direct JWT parsing with proper validation.
//
//nolint:gocognit // JWT validation requires comprehensive checks for security
func (c *SSHConnector) validateSSHJWT(sshJWTString string) (connector.Identity, error) {
	// Register our custom SSH signing method for JWT parsing
	jwt.RegisterSigningMethod("SSH", func() jwt.SigningMethod {
		return &SSHSigningMethodServer{}
	})

	// Parse JWT directly (jwt-ssh-agent approach)
	token, err := jwt.Parse(sshJWTString, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing algorithm is our SSH method
		if token.Method.Alg() != "SSH" {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Extract public key from claims for verification
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return nil, errors.New("invalid claims format")
		}

		publicKeyB64, ok := claims["public_key"].(string)
		if !ok {
			return nil, errors.New("missing public_key claim")
		}

		// Decode and parse public key
		publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyB64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode public key: %w", err)
		}

		publicKey, err := ssh.ParsePublicKey(publicKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}

		return publicKey, nil
	})

	if err != nil {
		return connector.Identity{}, fmt.Errorf("failed to parse JWT: %w", err)
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return connector.Identity{}, errors.New("invalid JWT claims format")
	}

	// Validate required claims
	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		return connector.Identity{}, errors.New("missing or invalid sub claim")
	}

	aud, ok := claims["aud"].(string)
	if !ok || aud == "" {
		return connector.Identity{}, errors.New("missing or invalid aud claim")
	}

	// Validate audience - ensure this token is intended for our Dex instance
	if aud != "kubernetes" {
		return connector.Identity{}, fmt.Errorf("invalid audience: %s", aud)
	}

	iss, ok := claims["iss"].(string)
	if !ok || iss == "" {
		return connector.Identity{}, errors.New("missing or invalid iss claim")
	}

	// Validate issuer
	if !c.isAllowedIssuer(iss) {
		return connector.Identity{}, fmt.Errorf("invalid issuer: %s", iss)
	}

	// Validate expiration (critical security check)
	exp, ok := claims["exp"].(float64)
	if !ok {
		return connector.Identity{}, errors.New("missing or invalid exp claim")
	}

	if time.Unix(int64(exp), 0).Before(time.Now()) {
		return connector.Identity{}, errors.New("token has expired")
	}

	// Validate not before
	if nbfClaim, nbfOk := claims["nbf"].(float64); nbfOk {
		if time.Unix(int64(nbfClaim), 0).After(time.Now()) {
			return connector.Identity{}, errors.New("token not yet valid")
		}
	}

	// Extract key fingerprint for user lookup
	keyFingerprint, ok := claims["key_fingerprint"].(string)
	if !ok || keyFingerprint == "" {
		return connector.Identity{}, errors.New("missing or invalid key_fingerprint claim")
	}

	// Look up user info by username (sub claim) and verify key is authorized
	userInfo, err := c.findUserByUsernameAndKey(sub, keyFingerprint)
	if err != nil {
		return connector.Identity{}, fmt.Errorf("SSH authentication failed for user %s with key %s: %w", sub, keyFingerprint, err)
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

// findUserByUsernameAndKey finds a user by username and verifies the key is authorized.
// This provides O(1) lookup performance instead of searching all users.
func (c *SSHConnector) findUserByUsernameAndKey(username, keyFingerprint string) (UserInfo, error) {
	// First, check the new Users format (O(1) lookup)
	if userConfig, exists := c.config.Users[username]; exists {
		// Check if this key is authorized for this user
		for _, authorizedKey := range userConfig.Keys {
			if authorizedKey == keyFingerprint {
				// Return the user info with username filled in if not already set
				userInfo := userConfig.UserInfo
				if userInfo.Username == "" {
					userInfo.Username = username
				}
				return userInfo, nil
			}
		}
		return UserInfo{}, fmt.Errorf("key %s not authorized for user %s", keyFingerprint, username)
	}

	// Fall back to legacy AuthorizedKeys format for backward compatibility
	if c.config.AuthorizedKeys != nil {
		if userInfo, exists := c.config.AuthorizedKeys[keyFingerprint]; exists {
			// Verify the username matches
			if userInfo.Username == username {
				return userInfo, nil
			}
			return UserInfo{}, fmt.Errorf("key %s belongs to user %s, not %s", keyFingerprint, userInfo.Username, username)
		}
	}

	return UserInfo{}, fmt.Errorf("user %s not found or key %s not authorized", username, keyFingerprint)
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

// SSHSigningMethodServer implements JWT signing method for server-side SSH verification.
type SSHSigningMethodServer struct{}

// Alg returns the signing method algorithm identifier.
func (m *SSHSigningMethodServer) Alg() string {
	return "SSH"
}

// Sign is not implemented on server side (client-only operation).
func (m *SSHSigningMethodServer) Sign(signingString string, key interface{}) ([]byte, error) {
	return nil, errors.New("SSH signing not supported on server side")
}

// Verify verifies the JWT signature using the SSH public key.
func (m *SSHSigningMethodServer) Verify(signingString string, signature []byte, key interface{}) error {
	// Parse SSH public key
	publicKey, ok := key.(ssh.PublicKey)
	if !ok {
		return fmt.Errorf("SSH verification requires ssh.PublicKey, got %T", key)
	}

	// Decode the base64-encoded signature
	signatureStr := string(signature)
	signatureBytes, err := base64.StdEncoding.DecodeString(signatureStr)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	// For SSH signature verification, we need to construct the signature structure
	// The signature format follows SSH wire protocol
	sshSignature := &ssh.Signature{
		Format: publicKey.Type(), // Use key type as format
		Blob:   signatureBytes,
	}

	// Verify the signature
	err = publicKey.Verify([]byte(signingString), sshSignature)
	if err != nil {
		return fmt.Errorf("SSH signature verification failed: %w", err)
	}

	return nil
}
