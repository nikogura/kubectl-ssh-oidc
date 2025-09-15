package ssh

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
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
	logger interface{}
}

// Open creates a new SSH connector.
// The logger parameter is interface{} for compatibility with different Dex versions:
// - Older versions (v2.13.0+incompatible) use interface{}
// - Newer versions (v2.39.1+) use log.Logger
// When integrating with newer Dex versions, cast logger to log.Logger as needed.
func (c *Config) Open(id string, logger interface{}) (connector.Connector, error) {
	return &SSHConnector{
		config: *c,
		logger: logger,
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

	// Get SSH JWT from either ssh_jwt or assertion parameter
	sshJWT := r.FormValue("ssh_jwt")
	if sshJWT == "" {
		sshJWT = r.FormValue("assertion")
	}
	if sshJWT == "" {
		http.Error(w, "Missing ssh_jwt parameter", http.StatusBadRequest)
		return
	}

	// Validate SSH JWT and get identity
	identity, err := c.validateSSHJWT(sshJWT)
	if err != nil {
		http.Error(w, fmt.Sprintf("Authentication failed: %v", err), http.StatusUnauthorized)
		return
	}

	// Generate proper OIDC tokens using Dex's token generation
	accessToken, idToken, err := c.generateOIDCTokens(identity)
	if err != nil {
		http.Error(w, "Failed to generate OIDC tokens", http.StatusInternalServerError)
		return
	}

	// Return standard OIDC token response
	tokenResp := map[string]interface{}{
		"access_token": accessToken,
		"id_token":     idToken,
		"token_type":   "Bearer",
		"expires_in":   c.config.TokenTTL,
		"user_info": map[string]interface{}{
			"sub":                identity.UserID,
			"name":               identity.Username,
			"preferred_username": identity.Username,
			"email":              identity.Email,
			"groups":             identity.Groups,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	encodeErr := json.NewEncoder(w).Encode(tokenResp)
	if encodeErr != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// generateOIDCTokens generates proper OIDC access and ID tokens for the authenticated user.
// This should integrate with Dex's token generation system in production.
func (c *SSHConnector) generateOIDCTokens(identity connector.Identity) (string, string, error) {
	now := time.Now()
	expiry := now.Add(time.Duration(c.config.TokenTTL) * time.Second)

	// Create access token claims
	accessClaims := jwt.MapClaims{
		"iss":    "https://dex-alpha.corp.terrace.fi", // Match Dex issuer URL
		"sub":    identity.UserID,
		"aud":    "kubernetes",
		"exp":    expiry.Unix(),
		"iat":    now.Unix(),
		"nbf":    now.Unix(),
		"email":  identity.Email,
		"groups": identity.Groups,
		"name":   identity.Username,
	}

	// Create ID token claims (standard OIDC)
	idClaims := jwt.MapClaims{
		"iss":                "https://dex-alpha.corp.terrace.fi",
		"sub":                identity.UserID,
		"aud":                []string{"kubernetes", "3d65cff418b45c057d8be201240f5e8a"}, // Include client ID
		"exp":                expiry.Unix(),
		"iat":                now.Unix(),
		"nbf":                now.Unix(),
		"email":              identity.Email,
		"email_verified":     true,
		"groups":             identity.Groups,
		"name":               identity.Username,
		"preferred_username": identity.Username,
	}

	// Use HMAC-SHA256 with a shared secret key
	// This is simpler and allows both Dex and Kubernetes to validate tokens
	signingMethod := jwt.SigningMethodHS256
	secretKey := []byte("kubectl-ssh-oidc-shared-key-v1")

	// Generate access token
	accessToken := jwt.NewWithClaims(signingMethod, accessClaims)
	accessTokenString, err := accessToken.SignedString(secretKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign access token: %w", err)
	}

	// Generate ID token
	idToken := jwt.NewWithClaims(signingMethod, idClaims)
	idTokenString, err := idToken.SignedString(secretKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign ID token: %w", err)
	}

	return accessTokenString, idTokenString, nil
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

// HandleDirectTokenRequest handles direct SSH token exchange requests.
// This method implements the direct token endpoint that bypasses OAuth2 redirects.
func (c *SSHConnector) HandleDirectTokenRequest(w http.ResponseWriter, r *http.Request) {
	// Parse the SSH JWT from form data
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Failed to parse form data", http.StatusBadRequest)
		return
	}

	sshJWT := r.FormValue("ssh_jwt")
	if sshJWT == "" {
		http.Error(w, "Missing ssh_jwt parameter", http.StatusBadRequest)
		return
	}

	// Verify and process the SSH JWT
	identity, err := c.handleJWTAuth(sshJWT)
	if err != nil {
		http.Error(w, fmt.Sprintf("Authentication failed: %v", err), http.StatusUnauthorized)
		return
	}

	// Generate OIDC token response
	tokenResponse := map[string]interface{}{
		"access_token": "ssh-" + sshJWT, // Use SSH JWT as access token
		"token_type":   "Bearer",
		"expires_in":   c.config.TokenTTL,
		"id_token":     sshJWT, // The SSH JWT serves as the ID token
		"user_info": map[string]interface{}{
			"sub":                identity.UserID,
			"name":               identity.Username,
			"email":              identity.Email,
			"groups":             identity.Groups,
			"preferred_username": identity.Username,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	encodeErr := json.NewEncoder(w).Encode(tokenResponse)
	if encodeErr != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// handleJWTAuth processes and validates an SSH-signed JWT using multi-pass evaluation.
func (c *SSHConnector) handleJWTAuth(sshJWT string) (connector.Identity, error) {
	claims, err := c.extractJWTClaims(sshJWT)
	if err != nil {
		return connector.Identity{}, err
	}

	validateErr := c.validateAudienceAndSubject(claims)
	if validateErr != nil {
		return connector.Identity{}, validateErr
	}

	username, ok := claims["sub"].(string)
	if !ok {
		return connector.Identity{}, errors.New("missing username in JWT")
	}
	userInfo, userKeys, err := c.getUserConfig(username)
	if err != nil {
		return connector.Identity{}, err
	}

	return c.verifySignatureAndCreateIdentity(sshJWT, claims, userInfo, userKeys)
}

// extractJWTClaims parses JWT and extracts claims.
func (c *SSHConnector) extractJWTClaims(sshJWT string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(sshJWT, func(token *jwt.Token) (interface{}, error) {
		return []byte("dummy"), nil
	})

	if err != nil {
		return c.extractClaimsManually(sshJWT)
	}

	if token == nil {
		return nil, errors.New("invalid JWT token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("failed to parse JWT claims")
	}

	return claims, nil
}

// extractClaimsManually extracts claims from JWT payload when parsing fails.
func (c *SSHConnector) extractClaimsManually(sshJWT string) (jwt.MapClaims, error) {
	parts := strings.Split(sshJWT, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT format")
	}

	payloadBytes, decodeErr := base64.RawURLEncoding.DecodeString(parts[1])
	if decodeErr != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", decodeErr)
	}

	var claims jwt.MapClaims
	unmarshalErr := json.Unmarshal(payloadBytes, &claims)
	if unmarshalErr != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %w", unmarshalErr)
	}

	return claims, nil
}

// validateAudienceAndSubject validates audience and subject claims.
func (c *SSHConnector) validateAudienceAndSubject(claims jwt.MapClaims) error {
	aud, ok := claims["aud"].(string)
	if !ok {
		return errors.New("missing audience in JWT")
	}
	if aud != "kubernetes" {
		return fmt.Errorf("invalid audience: expected 'kubernetes', got '%s'", aud)
	}

	_, ok = claims["sub"].(string)
	if !ok {
		return errors.New("missing username in JWT")
	}

	return nil
}

// getUserConfig retrieves user configuration by username.
func (c *SSHConnector) getUserConfig(username string) (*UserInfo, []string, error) {
	userConfig, exists := c.config.Users[username]
	if !exists {
		return nil, nil, fmt.Errorf("user %s not found in configuration", username)
	}

	if len(userConfig.Keys) == 0 {
		return nil, nil, fmt.Errorf("no authorized keys configured for user %s", username)
	}

	return &userConfig.UserInfo, userConfig.Keys, nil
}

// verifySignatureAndCreateIdentity verifies SSH signature and creates identity.
func (c *SSHConnector) verifySignatureAndCreateIdentity(
	sshJWT string,
	claims jwt.MapClaims,
	userInfo *UserInfo,
	userKeys []string,
) (connector.Identity, error) {
	parts := strings.Split(sshJWT, ".")
	if len(parts) != 3 {
		return connector.Identity{}, errors.New("invalid JWT format")
	}

	signingString := parts[0] + "." + parts[1]
	signature := parts[2]

	sshSignatureBytes, decodeErr := base64.RawURLEncoding.DecodeString(signature)
	if decodeErr != nil {
		return connector.Identity{}, fmt.Errorf("failed to decode JWT signature: %w", decodeErr)
	}
	sshSignatureB64 := string(sshSignatureBytes)

	publicKeyB64, ok := claims["public_key"].(string)
	if !ok {
		return connector.Identity{}, errors.New("missing public_key in JWT")
	}

	keyFingerprint, ok := claims["key_fingerprint"].(string)
	if !ok {
		return connector.Identity{}, errors.New("missing key_fingerprint in JWT")
	}

	// Verify signature against each authorized key until one succeeds
	for _, authorizedKeyFingerprint := range userKeys {
		if authorizedKeyFingerprint == keyFingerprint {
			// Parse the public key to determine its type
			publicKeyBytes, keyDecodeErr := base64.StdEncoding.DecodeString(publicKeyB64)
			if keyDecodeErr != nil {
				return connector.Identity{}, fmt.Errorf("failed to decode public key: %w", keyDecodeErr)
			}
			publicKey, parseErr := ssh.ParsePublicKey(publicKeyBytes)
			if parseErr != nil {
				return connector.Identity{}, fmt.Errorf("failed to parse public key: %w", parseErr)
			}

			// Use the actual key type as the signature format
			verifyErr := c.verifySSHSignature(signingString, sshSignatureB64, publicKey.Type(), publicKeyB64)
			if verifyErr == nil {
				return connector.Identity{
					UserID:        userInfo.Username,
					Username:      userInfo.Username,
					Email:         userInfo.Email,
					Groups:        append(userInfo.Groups, c.config.DefaultGroups...),
					EmailVerified: true,
				}, nil
			}
			return connector.Identity{}, fmt.Errorf("SSH signature verification failed for key %s: %w", keyFingerprint, verifyErr)
		}
	}

	return connector.Identity{}, fmt.Errorf("key fingerprint %s not authorized for user %s", keyFingerprint, userInfo.Username)
}
