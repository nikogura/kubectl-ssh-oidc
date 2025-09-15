package ssh

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/log"
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

// TokenResponse represents the direct token response for CLI tools.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// SSHConnector implements the Dex connector interface for SSH key authentication.
type SSHConnector struct {
	config Config
	logger log.Logger
}

// Open creates a new SSH connector with the correct Dex interface signature.
func (c *Config) Open(id string, logger log.Logger) (connector.Connector, error) {
	logger.Infof("SSH connector: initializing connector with ID %s", id)
	logger.Debugf("SSH connector: configured with %d users, %d allowed issuers, %d default groups",
		len(c.Users), len(c.AllowedIssuers), len(c.DefaultGroups))
	
	// Log configured users (without sensitive key data)
	for username, userConfig := range c.Users {
		logger.Debugf("SSH connector: user %s configured with %d keys, groups: %v",
			username, len(userConfig.Keys), userConfig.Groups)
	}
	
	return &SSHConnector{
		config: *c,
		logger: logger,
	}, nil
}

// LoginURL returns the URL for SSH-based login.
func (c *SSHConnector) LoginURL(scopes connector.Scopes, callbackURL, state string) (string, error) {
	c.logger.Infof("SSH connector: generating login URL for state %s, callback %s", state, callbackURL)
	// For SSH authentication, we use the standard callback URL
	// Clients POST SSH-signed JWTs directly to this URL
	loginURL := fmt.Sprintf("%s?state=%s", callbackURL, state)
	c.logger.Debugf("SSH connector: generated login URL: %s", loginURL)
	return loginURL, nil
}

// HandleCallback processes the SSH authentication callback.
// For CLI tools, this endpoint validates SSH JWTs and returns tokens directly.
func (c *SSHConnector) HandleCallback(scopes connector.Scopes, r *http.Request) (identity connector.Identity, err error) {
	c.logger.Infof("SSH connector: processing direct token request")
	c.logger.Debugf("SSH connector: request method %s, URL %s", r.Method, r.URL.String())
	
	// Handle both POST (form data) and GET (query param) for CLI compatibility
	var sshJWT string
	if r.Method == "POST" {
		sshJWT = r.FormValue("ssh_jwt")
	} else {
		sshJWT = r.URL.Query().Get("ssh_jwt")
	}
	
	if sshJWT == "" {
		c.logger.Errorf("SSH connector: no SSH JWT provided in request")
		return identity, errors.New("no SSH JWT provided")
	}

	c.logger.Infof("SSH connector: received SSH JWT, starting validation")
	// Validate and extract identity
	identity, err = c.validateSSHJWT(sshJWT)
	if err != nil {
		c.logger.Errorf("SSH connector: JWT validation failed: %v", err)
		return identity, err
	}
	
	c.logger.Infof("SSH connector: authentication successful for user %s (%s)", identity.Username, identity.Email)
	return identity, nil
}

// HandleDirectTokenRequest processes direct token requests from CLI tools.
// This bypasses the OAuth2 redirect flow and returns tokens directly.
func (c *SSHConnector) HandleDirectTokenRequest(w http.ResponseWriter, r *http.Request) {
	c.logger.Infof("SSH connector: processing direct token request")
	c.logger.Debugf("SSH connector: request method %s, URL %s", r.Method, r.URL.String())

	// Parse request to get SSH JWT
	var sshJWT string
	if r.Method == "POST" {
		if err := r.ParseForm(); err != nil {
			c.logger.Errorf("SSH connector: failed to parse form: %v", err)
			http.Error(w, "failed to parse form", http.StatusBadRequest)
			return
		}
		sshJWT = r.FormValue("ssh_jwt")
	} else {
		sshJWT = r.URL.Query().Get("ssh_jwt")
	}

	if sshJWT == "" {
		c.logger.Errorf("SSH connector: no SSH JWT provided in request")
		http.Error(w, "no SSH JWT provided", http.StatusBadRequest)
		return
	}

	// Validate SSH JWT and get identity
	c.logger.Infof("SSH connector: validating SSH JWT for direct token exchange")
	identity, err := c.validateSSHJWT(sshJWT)
	if err != nil {
		c.logger.Errorf("SSH connector: JWT validation failed: %v", err)
		http.Error(w, fmt.Sprintf("SSH authentication failed: %v", err), http.StatusUnauthorized)
		return
	}

	c.logger.Infof("SSH connector: SSH JWT validated successfully for user %s", identity.Username)

	// Generate tokens directly
	tokenResp, err := c.generateTokenResponse(identity)
	if err != nil {
		c.logger.Errorf("SSH connector: failed to generate tokens: %v", err)
		http.Error(w, "failed to generate tokens", http.StatusInternalServerError)
		return
	}

	// Return tokens as JSON
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(tokenResp); err != nil {
		c.logger.Errorf("SSH connector: failed to encode token response: %v", err)
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}

	c.logger.Infof("SSH connector: successfully issued tokens for user %s", identity.Username)
}

// generateTokenResponse creates an OIDC token response for the authenticated user.
func (c *SSHConnector) generateTokenResponse(identity connector.Identity) (*TokenResponse, error) {
	c.logger.Debugf("SSH connector: generating token response for user %s", identity.Username)

	// Create ID token claims
	now := time.Now()
	expiresIn := c.config.TokenTTL
	if expiresIn == 0 {
		expiresIn = 3600 // Default 1 hour
	}

	idTokenClaims := jwt.MapClaims{
		"iss":              "http://localhost:5556/dex", // Should match issuer
		"sub":              identity.UserID,
		"aud":              "kubectl-ssh-oidc", // Client ID
		"iat":              now.Unix(),
		"exp":              now.Add(time.Duration(expiresIn) * time.Second).Unix(),
		"email":            identity.Email,
		"email_verified":   identity.EmailVerified,
		"name":             identity.Username,
		"preferred_username": identity.Username,
		"groups":           identity.Groups,
	}

	// Sign ID token (using a simple signing key for demo - in production use proper key management)
	idToken := jwt.NewWithClaims(jwt.SigningMethodHS256, idTokenClaims)
	idTokenString, err := idToken.SignedString([]byte("demo-secret-key"))
	if err != nil {
		return nil, fmt.Errorf("failed to sign ID token: %w", err)
	}

	// Create access token (simplified for demo)
	accessTokenClaims := jwt.MapClaims{
		"iss":    "http://localhost:5556/dex",
		"sub":    identity.UserID,
		"aud":    "kubectl-ssh-oidc",
		"iat":    now.Unix(),
		"exp":    now.Add(time.Duration(expiresIn) * time.Second).Unix(),
		"email":  identity.Email,
		"groups": identity.Groups,
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessTokenClaims)
	accessTokenString, err := accessToken.SignedString([]byte("demo-secret-key"))
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	return &TokenResponse{
		AccessToken: accessTokenString,
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn,
		IDToken:     idTokenString,
	}, nil
}

// validateSSHJWT validates an SSH-signed JWT and extracts user identity.
// Updated for jwt-ssh-agent approach: direct JWT parsing with proper validation.
//
//nolint:gocognit // JWT validation requires comprehensive checks for security
func (c *SSHConnector) validateSSHJWT(sshJWTString string) (connector.Identity, error) {
	c.logger.Debugf("SSH connector: starting JWT validation")
	
	// Register our custom SSH signing method for JWT parsing
	jwt.RegisterSigningMethod("SSH", func() jwt.SigningMethod {
		return &SSHSigningMethodServer{}
	})

	// Parse JWT directly (jwt-ssh-agent approach)
	c.logger.Debugf("SSH connector: parsing JWT token")
	token, err := jwt.Parse(sshJWTString, func(token *jwt.Token) (interface{}, error) {
		c.logger.Debugf("SSH connector: JWT validation callback - checking signing method")
		// Verify the signing algorithm is our SSH method
		if token.Method.Alg() != "SSH" {
			c.logger.Errorf("SSH connector: unexpected signing method: %v", token.Header["alg"])
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		c.logger.Debugf("SSH connector: signing method verified as SSH")

		// Extract public key from claims for verification
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.logger.Errorf("SSH connector: invalid claims format")
			return nil, errors.New("invalid claims format")
		}

		publicKeyB64, ok := claims["public_key"].(string)
		if !ok {
			c.logger.Errorf("SSH connector: missing public_key claim")
			return nil, errors.New("missing public_key claim")
		}
		c.logger.Debugf("SSH connector: found public_key claim in JWT")

		// Decode and parse public key
		publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyB64)
		if err != nil {
			c.logger.Errorf("SSH connector: failed to decode public key: %v", err)
			return nil, fmt.Errorf("failed to decode public key: %w", err)
		}

		publicKey, err := ssh.ParsePublicKey(publicKeyBytes)
		if err != nil {
			c.logger.Errorf("SSH connector: failed to parse public key: %v", err)
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}
		c.logger.Debugf("SSH connector: successfully parsed public key, type: %s", publicKey.Type())

		return publicKey, nil
	})

	if err != nil {
		c.logger.Errorf("SSH connector: failed to parse JWT: %v", err)
		return connector.Identity{}, fmt.Errorf("failed to parse JWT: %w", err)
	}
	c.logger.Debugf("SSH connector: JWT parsed successfully")

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.logger.Errorf("SSH connector: invalid JWT claims format")
		return connector.Identity{}, errors.New("invalid JWT claims format")
	}
	c.logger.Debugf("SSH connector: extracted JWT claims")

	// Validate required claims
	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		c.logger.Errorf("SSH connector: missing or invalid sub claim")
		return connector.Identity{}, errors.New("missing or invalid sub claim")
	}
	c.logger.Debugf("SSH connector: found sub claim: %s", sub)

	aud, ok := claims["aud"].(string)
	if !ok || aud == "" {
		c.logger.Errorf("SSH connector: missing or invalid aud claim")
		return connector.Identity{}, errors.New("missing or invalid aud claim")
	}
	c.logger.Debugf("SSH connector: found aud claim: %s", aud)

	// Validate audience - ensure this token is intended for our Dex instance
	if aud != "kubernetes" {
		c.logger.Errorf("SSH connector: invalid audience: %s (expected: kubernetes)", aud)
		return connector.Identity{}, fmt.Errorf("invalid audience: %s", aud)
	}
	c.logger.Debugf("SSH connector: audience validation passed")

	iss, ok := claims["iss"].(string)
	if !ok || iss == "" {
		c.logger.Errorf("SSH connector: missing or invalid iss claim")
		return connector.Identity{}, errors.New("missing or invalid iss claim")
	}
	c.logger.Debugf("SSH connector: found iss claim: %s", iss)

	// Validate issuer
	if !c.isAllowedIssuer(iss) {
		c.logger.Errorf("SSH connector: invalid issuer: %s (allowed: %v)", iss, c.config.AllowedIssuers)
		return connector.Identity{}, fmt.Errorf("invalid issuer: %s", iss)
	}
	c.logger.Debugf("SSH connector: issuer validation passed")

	// Validate expiration (critical security check)
	exp, ok := claims["exp"].(float64)
	if !ok {
		c.logger.Errorf("SSH connector: missing or invalid exp claim")
		return connector.Identity{}, errors.New("missing or invalid exp claim")
	}

	expTime := time.Unix(int64(exp), 0)
	if expTime.Before(time.Now()) {
		c.logger.Errorf("SSH connector: token has expired (exp: %v, now: %v)", expTime, time.Now())
		return connector.Identity{}, errors.New("token has expired")
	}
	c.logger.Debugf("SSH connector: token expiration validation passed (exp: %v)", expTime)

	// Validate not before
	if nbfClaim, nbfOk := claims["nbf"].(float64); nbfOk {
		nbfTime := time.Unix(int64(nbfClaim), 0)
		if nbfTime.After(time.Now()) {
			c.logger.Errorf("SSH connector: token not yet valid (nbf: %v, now: %v)", nbfTime, time.Now())
			return connector.Identity{}, errors.New("token not yet valid")
		}
		c.logger.Debugf("SSH connector: token not-before validation passed (nbf: %v)", nbfTime)
	}

	// Extract key fingerprint for user lookup
	keyFingerprint, ok := claims["key_fingerprint"].(string)
	if !ok || keyFingerprint == "" {
		c.logger.Errorf("SSH connector: missing or invalid key_fingerprint claim")
		return connector.Identity{}, errors.New("missing or invalid key_fingerprint claim")
	}
	c.logger.Debugf("SSH connector: found key_fingerprint claim: %s", keyFingerprint)

	// Look up user info by username (sub claim) and verify key is authorized
	c.logger.Debugf("SSH connector: looking up user %s with key %s", sub, keyFingerprint)
	userInfo, err := c.findUserByUsernameAndKey(sub, keyFingerprint)
	if err != nil {
		c.logger.Errorf("SSH connector: user lookup failed for %s with key %s: %v", sub, keyFingerprint, err)
		return connector.Identity{}, fmt.Errorf("SSH authentication failed for user %s with key %s: %w", sub, keyFingerprint, err)
	}
	c.logger.Infof("SSH connector: user lookup successful for %s", sub)

	// Build identity
	identity := connector.Identity{
		UserID:        userInfo.Username,
		Username:      userInfo.Username,
		Email:         userInfo.Email,
		EmailVerified: true,
		Groups:        append(userInfo.Groups, c.config.DefaultGroups...),
	}
	c.logger.Infof("SSH connector: built identity for user %s with %d groups", identity.Username, len(identity.Groups))
	c.logger.Debugf("SSH connector: user groups: %v", identity.Groups)

	return identity, nil
}

// findUserByUsernameAndKey finds a user by username and verifies the key is authorized.
// This provides O(1) lookup performance instead of searching all users.
func (c *SSHConnector) findUserByUsernameAndKey(username, keyFingerprint string) (UserInfo, error) {
	c.logger.Debugf("SSH connector: looking up user %s with key fingerprint %s", username, keyFingerprint)
	
	// First, check the new Users format (O(1) lookup)
	if userConfig, exists := c.config.Users[username]; exists {
		c.logger.Debugf("SSH connector: found user %s in Users config with %d authorized keys", username, len(userConfig.Keys))
		// Check if this key is authorized for this user
		for i, authorizedKey := range userConfig.Keys {
			c.logger.Debugf("SSH connector: checking key %d: %s", i+1, authorizedKey)
			if authorizedKey == keyFingerprint {
				c.logger.Infof("SSH connector: key %s authorized for user %s", keyFingerprint, username)
				// Return the user info with username filled in if not already set
				userInfo := userConfig.UserInfo
				if userInfo.Username == "" {
					userInfo.Username = username
				}
				return userInfo, nil
			}
		}
		c.logger.Errorf("SSH connector: key %s not found in authorized keys for user %s", keyFingerprint, username)
		return UserInfo{}, fmt.Errorf("key %s not authorized for user %s", keyFingerprint, username)
	}
	c.logger.Debugf("SSH connector: user %s not found in Users config, trying legacy AuthorizedKeys", username)

	// Fall back to legacy AuthorizedKeys format for backward compatibility
	if c.config.AuthorizedKeys != nil {
		c.logger.Debugf("SSH connector: checking legacy AuthorizedKeys format with %d entries", len(c.config.AuthorizedKeys))
		if userInfo, exists := c.config.AuthorizedKeys[keyFingerprint]; exists {
			c.logger.Debugf("SSH connector: found key %s in legacy format, username: %s", keyFingerprint, userInfo.Username)
			// Verify the username matches
			if userInfo.Username == username {
				c.logger.Infof("SSH connector: legacy key %s authorized for user %s", keyFingerprint, username)
				return userInfo, nil
			}
			c.logger.Errorf("SSH connector: key %s belongs to user %s, not %s", keyFingerprint, userInfo.Username, username)
			return UserInfo{}, fmt.Errorf("key %s belongs to user %s, not %s", keyFingerprint, userInfo.Username, username)
		}
		c.logger.Debugf("SSH connector: key %s not found in legacy AuthorizedKeys", keyFingerprint)
	} else {
		c.logger.Debugf("SSH connector: no legacy AuthorizedKeys configured")
	}

	c.logger.Errorf("SSH connector: user %s not found or key %s not authorized in any configuration", username, keyFingerprint)
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