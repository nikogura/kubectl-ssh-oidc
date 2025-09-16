package ssh

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/dexidp/dex/connector"
	"github.com/go-jose/go-jose/v4"
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

	// AllowedClients specifies which OAuth2 client IDs are allowed to use this connector
	AllowedClients []string `json:"allowed_clients"`
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
	config          Config
	logger          interface{}
	signingKeys     []*rsa.PrivateKey // Multiple Dex RSA signing keys to try
	keyIDs          []string          // Corresponding key IDs for JWT headers
	currentKeyIndex int               // Index of currently selected key
}

// Open creates a new SSH connector.
// The logger parameter is interface{} for compatibility with different Dex versions:
// - Older versions (v2.13.0+incompatible) use interface{}
// - Newer versions (v2.39.1+) use log.Logger
// When integrating with newer Dex versions, cast logger to log.Logger as needed.
func (c *Config) Open(id string, logger interface{}) (connector.Connector, error) {
	// Log version information when SSH connector starts up
	version := GetVersion()

	// Try to log using different logger interfaces for compatibility
	if dexLogger, ok := logger.(interface{ Infof(string, ...interface{}) }); ok {
		dexLogger.Infof("SSH connector starting - version: %s", version)
	} else {
		// Fallback: use fmt if logger interface is not available
		fmt.Printf("SSH connector starting - version: %s\n", version)
	}

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
	// Handle both SSH JWT directly and as authorization code
	var sshJWT string

	// First try direct SSH JWT parameter
	sshJWT = r.FormValue("ssh_jwt")

	// If not found, try as authorization code
	if sshJWT == "" {
		sshJWT = r.FormValue("code")
	}

	if sshJWT == "" {
		return identity, errors.New("no SSH JWT or authorization code provided")
	}

	// Validate and extract identity - this will now work with Dex's standard token generation
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

	clientID := r.FormValue("client_id")
	if clientID == "" {
		http.Error(w, "Missing client_id parameter", http.StatusBadRequest)
		return
	}

	// Validate client ID against allowed clients
	allowed := false
	for _, allowedClient := range c.config.AllowedClients {
		if clientID == allowedClient {
			allowed = true
			break
		}
	}
	if !allowed {
		http.Error(w, "Unauthorized client ID", http.StatusUnauthorized)
		return
	}

	// Validate SSH JWT and get identity
	identity, err := c.validateSSHJWT(sshJWT)
	if err != nil {
		http.Error(w, fmt.Sprintf("Authentication failed: %v", err), http.StatusUnauthorized)
		return
	}

	// Generate multiple token options with all available signing keys
	tokenOptions, err := c.generateAllTokenOptions(identity, clientID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to generate token options: %v", err), http.StatusInternalServerError)
		return
	}

	// Return response with multiple token options for client to try
	tokenResp := map[string]interface{}{
		"token_type": "Bearer",
		"expires_in": c.config.TokenTTL,
		"tokens":     tokenOptions,
		"user_info": map[string]interface{}{
			"sub":                identity.UserID,
			"name":               identity.Username,
			"preferred_username": identity.Username,
			"email":              identity.Email,
			"groups":             identity.Groups,
		},
	}

	// For backward compatibility, also include first token as primary
	if len(tokenOptions) > 0 {
		firstOption := tokenOptions[0]
		if accessToken, ok := firstOption["access_token"].(string); ok {
			tokenResp["access_token"] = accessToken
		}
		if idToken, ok := firstOption["id_token"].(string); ok {
			tokenResp["id_token"] = idToken
		}
	}

	w.Header().Set("Content-Type", "application/json")
	encodeErr := json.NewEncoder(w).Encode(tokenResp)
	if encodeErr != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// generateRSASignedTokens generates OIDC tokens using RSA signing that Kubernetes can validate.
// This uses a fixed RSA key pair for consistency with Kubernetes OIDC configuration.
func (c *SSHConnector) generateRSASignedTokens(identity connector.Identity, clientID string) (string, string, error) {
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
		"aud":                []string{"kubernetes", clientID}, // Include validated client ID
		"exp":                expiry.Unix(),
		"iat":                now.Unix(),
		"nbf":                now.Unix(),
		"email":              identity.Email,
		"email_verified":     true,
		"groups":             identity.Groups,
		"name":               identity.Username,
		"preferred_username": identity.Username,
	}

	// Get or generate RSA signing key
	signingKey, err := c.getSigningKey()
	if err != nil {
		return "", "", fmt.Errorf("failed to get signing key: %w", err)
	}

	// Use RS256 signing method (RSA with SHA-256)
	signingMethod := jwt.SigningMethodRS256

	// Generate access token with proper kid header
	accessToken := jwt.NewWithClaims(signingMethod, accessClaims)
	if keyID := c.getCurrentKeyID(); keyID != "" {
		accessToken.Header["kid"] = keyID
	}
	// Remove typ header to match standard Dex OIDC tokens
	delete(accessToken.Header, "typ")
	accessTokenString, err := accessToken.SignedString(signingKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign access token: %w", err)
	}

	// Generate ID token with proper kid header
	idToken := jwt.NewWithClaims(signingMethod, idClaims)
	if keyID := c.getCurrentKeyID(); keyID != "" {
		idToken.Header["kid"] = keyID
	}
	// Remove typ header to match standard Dex OIDC tokens
	delete(idToken.Header, "typ")
	idTokenString, err := idToken.SignedString(signingKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign ID token: %w", err)
	}

	return accessTokenString, idTokenString, nil
}

// generateAllTokenOptions generates OIDC tokens with all available signing keys.
// Returns multiple token options that the client can try until one works with Kubernetes.
func (c *SSHConnector) generateAllTokenOptions(identity connector.Identity, clientID string) ([]map[string]interface{}, error) {
	if len(c.signingKeys) == 0 {
		return nil, errors.New("no signing keys available")
	}

	now := time.Now()
	expiry := now.Add(time.Duration(c.config.TokenTTL) * time.Second)
	var tokenOptions []map[string]interface{}

	fmt.Printf("DEBUG: SSH connector generating tokens with %d signing keys\n", len(c.signingKeys))

	// Generate tokens with each available signing key
	for i, signingKey := range c.signingKeys {
		keyID := ""
		if i < len(c.keyIDs) {
			keyID = c.keyIDs[i]
		}

		fmt.Printf("DEBUG: Generating token with signing key %d/%d (keyID: %s)\n", i+1, len(c.signingKeys), keyID)

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
			"aud":                []string{"kubernetes", clientID}, // Include validated client ID
			"exp":                expiry.Unix(),
			"iat":                now.Unix(),
			"nbf":                now.Unix(),
			"email":              identity.Email,
			"email_verified":     true,
			"groups":             identity.Groups,
			"name":               identity.Username,
			"preferred_username": identity.Username,
		}

		// Use RSA-SHA256 signing method
		signingMethod := jwt.SigningMethodRS256

		// Generate access token
		accessToken := jwt.NewWithClaims(signingMethod, accessClaims)
		if keyID != "" {
			accessToken.Header["kid"] = keyID
		}
		delete(accessToken.Header, "typ")
		accessTokenString, err := accessToken.SignedString(signingKey)
		if err != nil {
			fmt.Printf("DEBUG: Failed to sign access token with key %d: %v\n", i+1, err)
			continue // Skip this key and try the next one
		}

		// Generate ID token with proper kid header
		idToken := jwt.NewWithClaims(signingMethod, idClaims)
		if keyID != "" {
			idToken.Header["kid"] = keyID
		}
		// Remove typ header to match standard Dex OIDC tokens
		delete(idToken.Header, "typ")
		idTokenString, err := idToken.SignedString(signingKey)
		if err != nil {
			fmt.Printf("DEBUG: Failed to sign ID token with key %d: %v\n", i+1, err)
			continue // Skip this key and try the next one
		}

		// Create token option
		tokenOption := map[string]interface{}{
			"access_token": accessTokenString,
			"id_token":     idTokenString,
			"kid":          keyID,
		}

		tokenOptions = append(tokenOptions, tokenOption)
		fmt.Printf("DEBUG: Successfully generated token option %d with keyID: %s\n", len(tokenOptions), keyID)
	}

	if len(tokenOptions) == 0 {
		return nil, errors.New("failed to generate tokens with any available signing key")
	}

	fmt.Printf("DEBUG: Generated %d token options\n", len(tokenOptions))
	return tokenOptions, nil
}

// getSigningKey returns the current Dex RSA private key for token signing.
func (c *SSHConnector) getSigningKey() (*rsa.PrivateKey, error) {
	if len(c.signingKeys) == 0 {
		fmt.Printf("DEBUG: SSH connector has no signing keys - SetSigningKeyFromInterface was never called\n")
		return nil, errors.New("no signing keys available: SSH connector must receive Dex's signing keys via SetSigningKeyFromInterface")
	}

	if c.currentKeyIndex >= len(c.signingKeys) {
		return nil, errors.New("current key index out of range")
	}

	currentKeyID := ""
	if c.currentKeyIndex < len(c.keyIDs) {
		currentKeyID = c.keyIDs[c.currentKeyIndex]
	}

	fmt.Printf("DEBUG: SSH connector using signing key %d/%d (keyID: %s)\n",
		c.currentKeyIndex+1, len(c.signingKeys), currentKeyID)

	return c.signingKeys[c.currentKeyIndex], nil
}

// getCurrentKeyID returns the current key ID for JWT headers.
func (c *SSHConnector) getCurrentKeyID() string {
	if c.currentKeyIndex < len(c.keyIDs) {
		return c.keyIDs[c.currentKeyIndex]
	}
	return ""
}

// SetSigningKey sets Dex's RSA signing key for token generation.
// This should be called during SSH connector initialization with Dex's actual key.
func (c *SSHConnector) SetSigningKey(key *rsa.PrivateKey) {
	c.signingKeys = []*rsa.PrivateKey{key}
	c.keyIDs = []string{""}
	c.currentKeyIndex = 0
}

// AddSigningKey adds another signing key to try (for key iteration).
func (c *SSHConnector) AddSigningKey(key *rsa.PrivateKey, keyID string) {
	c.signingKeys = append(c.signingKeys, key)
	c.keyIDs = append(c.keyIDs, keyID)
}

// SetSigningKeyFromInterface allows external code to set the signing key from any private key interface.
// This is useful when Dex provides keys in different formats.
func (c *SSHConnector) SetSigningKeyFromInterface(key interface{}) error {
	// DEBUG: Log that SetSigningKeyFromInterface is being called
	fmt.Printf("DEBUG: SSH connector SetSigningKeyFromInterface called with key type: %T\n", key)

	switch k := key.(type) {
	case *rsa.PrivateKey:
		// Initialize with first key
		if len(c.signingKeys) == 0 {
			c.signingKeys = []*rsa.PrivateKey{k}
			c.keyIDs = []string{""}
			c.currentKeyIndex = 0
		} else {
			c.signingKeys = append(c.signingKeys, k)
			c.keyIDs = append(c.keyIDs, "")
		}
		fmt.Printf("DEBUG: SSH connector added raw RSA private key (no keyID)\n")
		return nil
	case *jose.JSONWebKey:
		// Extract RSA private key from JOSE key
		if rsaKey, ok := k.Key.(*rsa.PrivateKey); ok {
			// Initialize with first key
			if len(c.signingKeys) == 0 {
				c.signingKeys = []*rsa.PrivateKey{rsaKey}
				c.keyIDs = []string{k.KeyID}
				c.currentKeyIndex = 0
			} else {
				c.signingKeys = append(c.signingKeys, rsaKey)
				c.keyIDs = append(c.keyIDs, k.KeyID)
			}
			fmt.Printf("DEBUG: SSH connector added JOSE key with keyID: %s (total keys: %d)\n", k.KeyID, len(c.signingKeys))
			return nil
		}
		return fmt.Errorf("JSONWebKey does not contain RSA private key, got: %T", k.Key)
	default:
		return fmt.Errorf("unsupported key type: %T", key)
	}
}

// TryNextKey switches to the next available signing key (for key iteration).
func (c *SSHConnector) TryNextKey() bool {
	if c.currentKeyIndex+1 < len(c.signingKeys) {
		c.currentKeyIndex++
		fmt.Printf("DEBUG: SSH connector switched to key %d/%d (keyID: %s)\n",
			c.currentKeyIndex+1, len(c.signingKeys), c.getCurrentKeyID())
		return true
	}
	return false
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
// This generates RSA-signed tokens that Kubernetes can validate.
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

	clientID := r.FormValue("client_id")
	if clientID == "" {
		http.Error(w, "Missing client_id parameter", http.StatusBadRequest)
		return
	}

	// Validate client ID against allowed clients
	allowed := false
	for _, allowedClient := range c.config.AllowedClients {
		if clientID == allowedClient {
			allowed = true
			break
		}
	}
	if !allowed {
		http.Error(w, "Unauthorized client ID", http.StatusUnauthorized)
		return
	}

	// Verify and process the SSH JWT
	identity, err := c.validateSSHJWT(sshJWT)
	if err != nil {
		http.Error(w, fmt.Sprintf("Authentication failed: %v", err), http.StatusUnauthorized)
		return
	}

	// Generate RSA-signed OIDC tokens that Kubernetes can validate
	accessToken, idToken, err := c.generateRSASignedTokens(identity, clientID)
	if err != nil {
		http.Error(w, "Failed to generate tokens", http.StatusInternalServerError)
		return
	}

	// Return standard OIDC token response
	tokenResponse := map[string]interface{}{
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
	encodeErr := json.NewEncoder(w).Encode(tokenResponse)
	if encodeErr != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}
