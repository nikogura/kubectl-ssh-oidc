package ssh

import (
	"encoding/base64"
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
	// For SSH authentication, we don't use a traditional login URL
	// Instead, clients directly present SSH-signed JWTs
	loginURL := fmt.Sprintf("%s?state=%s&ssh_auth=true", callbackURL, state)
	c.logger.Debugf("SSH connector: generated login URL: %s", loginURL)
	return loginURL, nil
}

// HandleCallback processes the SSH authentication callback.
func (c *SSHConnector) HandleCallback(scopes connector.Scopes, r *http.Request) (identity connector.Identity, err error) {
	c.logger.Infof("SSH connector: processing authentication callback")
	c.logger.Debugf("SSH connector: request method %s, URL %s", r.Method, r.URL.String())
	
	// Log all form parameters (excluding sensitive JWT content)
	for key, values := range r.Form {
		if key == "ssh_jwt" {
			c.logger.Debugf("SSH connector: form parameter %s present (JWT length: %d)", key, len(values[0]))
		} else {
			c.logger.Debugf("SSH connector: form parameter %s = %v", key, values)
		}
	}
	
	// Get the SSH JWT from the request
	sshJWT := r.FormValue("ssh_jwt")
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