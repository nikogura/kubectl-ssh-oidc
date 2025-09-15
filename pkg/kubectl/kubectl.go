package kubectl

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
)

// Constants for commonly used values.
const (
	trueString = "true"
)

// Sentinel errors.
var (
	errKeyNotFound = errors.New("key file not found")
)

// Config represents the plugin configuration.
type Config struct {
	DexURL         string   `json:"dex_url"`
	ClientID       string   `json:"client_id"`
	ClientSecret   string   `json:"client_secret"`
	Audience       string   `json:"audience"`
	CacheTokens    bool     `json:"cache_tokens"`
	Username       string   `json:"username,omitempty"`
	SSHKeyPaths    []string `json:"ssh_key_paths,omitempty"`   // Custom SSH key paths
	UseAgent       bool     `json:"use_agent"`                 // Whether to use ssh-agent
	IdentitiesOnly bool     `json:"identities_only,omitempty"` // Only use specified keys
}

// DexTokenResponse represents the response from Dex token endpoint.
type DexTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

// SSHKey represents a unified SSH key structure for both agent and filesystem keys.
type SSHKey struct {
	PublicKey   ssh.PublicKey
	Blob        []byte // Public key bytes
	Comment     string
	Signer      ssh.Signer // For filesystem keys
	AgentKey    *agent.Key // For agent keys (may be nil)
	Source      string     // "agent" or filesystem path
	Fingerprint string     // SHA256 fingerprint
}

// SSHClientInterface defines the unified SSH client interface.
type SSHClientInterface interface {
	GetKeys() ([]*SSHKey, error)
	SignWithKey(key *SSHKey, data []byte) (*ssh.Signature, ssh.PublicKey, error)
}

// UnifiedSSHClient provides access to both SSH agent and filesystem keys.
type UnifiedSSHClient struct {
	config         *Config
	agent          agent.ExtendedAgent // May be nil if agent not available
	agentAvailable bool
}

// SSHAgentClient wraps SSH agent functionality (legacy, for compatibility).
type SSHAgentClient struct {
	agent agent.ExtendedAgent
}

// NewUnifiedSSHClient creates a new unified SSH client that supports both agent and filesystem keys.
func NewUnifiedSSHClient(config *Config) (*UnifiedSSHClient, error) {
	client := &UnifiedSSHClient{
		config: config,
	}

	// Try to connect to SSH agent if enabled
	if config.UseAgent {
		if authSock := os.Getenv("SSH_AUTH_SOCK"); authSock != "" {
			dialer := &net.Dialer{}
			conn, err := dialer.DialContext(context.Background(), "unix", authSock)
			if err == nil {
				client.agent = agent.NewClient(conn)
				client.agentAvailable = true
			}
		}
	}

	return client, nil
}

// NewSSHAgentClient creates a new SSH agent client (legacy).
func NewSSHAgentClient() (*SSHAgentClient, error) {
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(context.Background(), "unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SSH agent: %w", err)
	}

	return &SSHAgentClient{
		agent: agent.NewClient(conn),
	}, nil
}

// GetKeys returns all SSH keys from both agent and filesystem following SSH client behavior.
func (c *UnifiedSSHClient) GetKeys() ([]*SSHKey, error) {
	var allKeys []*SSHKey

	// Get keys from SSH agent (if available and enabled)
	if c.agentAvailable && !c.config.IdentitiesOnly {
		agentKeys, err := c.getAgentKeys()
		if err == nil {
			allKeys = append(allKeys, agentKeys...)

			// If we have agent keys and no specific key paths requested, use agent keys only
			// This avoids decrypting filesystem keys unnecessarily
			if len(agentKeys) > 0 && len(c.config.SSHKeyPaths) == 0 {
				return allKeys, nil
			}
		}
		// Continue even if agent keys fail - this matches SSH behavior
	}

	// Get keys from filesystem (only if no agent keys found, or specific keys requested)
	fsKeys, err := c.getFilesystemKeys()
	if err != nil {
		if len(allKeys) == 0 {
			return nil, fmt.Errorf("failed to load SSH keys: %w", err)
		}
		// If we have agent keys, continue despite filesystem key errors
	} else {
		allKeys = append(allKeys, fsKeys...)
	}

	if len(allKeys) == 0 {
		return nil, errors.New("no SSH keys found in agent or filesystem")
	}

	return allKeys, nil
}

// getAgentKeys retrieves SSH keys from the SSH agent.
func (c *UnifiedSSHClient) getAgentKeys() ([]*SSHKey, error) {
	agentKeys, err := c.agent.List()
	if err != nil {
		return nil, fmt.Errorf("failed to list SSH agent keys: %w", err)
	}

	var sshKeys []*SSHKey
	for _, agentKey := range agentKeys {
		pubKey, parseErr := ssh.ParsePublicKey(agentKey.Blob)
		if parseErr != nil {
			continue // Skip invalid keys
		}

		sshKey := &SSHKey{
			PublicKey:   pubKey,
			Blob:        agentKey.Blob,
			Comment:     agentKey.Comment,
			AgentKey:    agentKey,
			Source:      "agent",
			Fingerprint: ssh.FingerprintSHA256(pubKey),
		}
		sshKeys = append(sshKeys, sshKey)
	}

	return sshKeys, nil
}

// getFilesystemKeys discovers and loads SSH keys from filesystem.
func (c *UnifiedSSHClient) getFilesystemKeys() ([]*SSHKey, error) {
	keyPaths := c.getSSHKeyPaths()
	var sshKeys []*SSHKey
	var keyErrors []error

	for _, keyPath := range keyPaths {
		key, err := c.loadSSHKeyFromFile(keyPath)
		if err != nil {
			if errors.Is(err, errKeyNotFound) {
				continue // Skip non-existent keys silently
			}
			keyErrors = append(keyErrors, fmt.Errorf("key %s: %w", keyPath, err))
			continue
		}
		if key != nil {
			sshKeys = append(sshKeys, key)
		}
	}

	// Return keys even if some failed to load (matches SSH behavior)
	if len(sshKeys) == 0 && len(keyErrors) > 0 {
		return nil, fmt.Errorf("failed to load any SSH keys: %v", keyErrors)
	}

	return sshKeys, nil
}

// getSSHKeyPaths returns SSH key paths to try, following SSH client behavior.
func (c *UnifiedSSHClient) getSSHKeyPaths() []string {
	// If specific paths are configured, use those
	if len(c.config.SSHKeyPaths) > 0 {
		return c.config.SSHKeyPaths
	}

	// Use standard SSH key locations (matches SSH client defaults)
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	sshDir := filepath.Join(homeDir, ".ssh")
	defaultKeys := []string{
		filepath.Join(sshDir, "id_rsa"),
		filepath.Join(sshDir, "id_ecdsa"),
		filepath.Join(sshDir, "id_ecdsa_sk"),
		filepath.Join(sshDir, "id_ed25519"),
		filepath.Join(sshDir, "id_ed25519_sk"),
		filepath.Join(sshDir, "id_dsa"), // Legacy, but still supported
	}

	return defaultKeys
}

// loadSSHKeyFromFile loads an SSH private key from filesystem with passphrase prompting.
func (c *UnifiedSSHClient) loadSSHKeyFromFile(keyPath string) (*SSHKey, error) {
	// Check if file exists
	_, statErr := os.Stat(keyPath)
	if os.IsNotExist(statErr) {
		return nil, errKeyNotFound // Skip non-existent keys silently (matches SSH behavior)
	}

	// Read private key file
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	// Try to parse key without passphrase first
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		// Key might be encrypted, try with passphrase
		signer, err = c.loadEncryptedKey(keyBytes, keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
	}

	// Load corresponding public key for metadata
	pubKeyPath := keyPath + ".pub"
	comment := filepath.Base(keyPath) // Default comment
	pubKeyBytes, pubErr := os.ReadFile(pubKeyPath)
	if pubErr == nil {
		// Extract comment from public key file
		pubKeyLine := strings.TrimSpace(string(pubKeyBytes))
		parts := strings.SplitN(pubKeyLine, " ", 3)
		if len(parts) >= 3 {
			comment = parts[2]
		}
	}

	pubKey := signer.PublicKey()
	sshKey := &SSHKey{
		PublicKey:   pubKey,
		Blob:        pubKey.Marshal(),
		Comment:     comment,
		Signer:      signer,
		Source:      keyPath,
		Fingerprint: ssh.FingerprintSHA256(pubKey),
	}

	return sshKey, nil
}

// loadEncryptedKey loads an encrypted SSH key with passphrase prompting.
func (c *UnifiedSSHClient) loadEncryptedKey(keyBytes []byte, keyPath string) (ssh.Signer, error) {
	// Determine if we're running interactively
	if !term.IsTerminal(syscall.Stdin) {
		return nil, errors.New("key is encrypted but no TTY available for passphrase prompt")
	}

	// Try up to 3 times for passphrase (matches SSH behavior)
	for attempt := 1; attempt <= 3; attempt++ {
		fmt.Fprintf(os.Stderr, "Enter passphrase for %s: ", keyPath)

		passphrase, err := term.ReadPassword(syscall.Stdin)
		fmt.Fprintln(os.Stderr) // Print newline after password input

		if err != nil {
			return nil, fmt.Errorf("failed to read passphrase: %w", err)
		}

		signer, err := ssh.ParsePrivateKeyWithPassphrase(keyBytes, passphrase)
		if err == nil {
			return signer, nil
		}

		if attempt < 3 {
			fmt.Fprintln(os.Stderr, "Bad passphrase, try again.")
		}
	}

	return nil, errors.New("failed to decrypt key after 3 attempts")
}

// SignWithKey signs data with the specified SSH key.
func (c *UnifiedSSHClient) SignWithKey(key *SSHKey, data []byte) (*ssh.Signature, ssh.PublicKey, error) {
	if key.AgentKey != nil {
		// Use SSH agent for signing
		signature, err := c.agent.Sign(key.AgentKey, data)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to sign with agent key: %w", err)
		}
		return signature, key.PublicKey, nil
	} else if key.Signer != nil {
		// Use filesystem key signer
		signature, err := key.Signer.Sign(nil, data)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to sign with filesystem key: %w", err)
		}
		return signature, key.PublicKey, nil
	}

	return nil, nil, errors.New("key has no valid signer")
}

// GetKeys returns all SSH keys from the agent.
func (c *SSHAgentClient) GetKeys() (keys []*agent.Key, err error) {
	keys, err = c.agent.List()
	if err != nil {
		return nil, fmt.Errorf("failed to list SSH keys: %w", err)
	}

	if len(keys) == 0 {
		return nil, errors.New("no SSH keys found in agent")
	}

	return keys, nil
}

// SignData signs data with the first available SSH key.
func (c *SSHAgentClient) SignData(data []byte) (*ssh.Signature, ssh.PublicKey, error) {
	keys, err := c.GetKeys()
	if err != nil {
		return nil, nil, err
	}

	// Use the first key for signing
	key := keys[0]
	return c.SignWithKey(key, data)
}

// SignWithKey signs data with a specific SSH key.
func (c *SSHAgentClient) SignWithKey(key *agent.Key, data []byte) (*ssh.Signature, ssh.PublicKey, error) {
	signature, err := c.agent.Sign(key, data)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign data: %w", err)
	}

	pubKey, err := ssh.ParsePublicKey(key.Blob)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return signature, pubKey, nil
}

// CreateSSHSignedJWT creates a JWT signed with SSH keys from agent and/or filesystem.
// Uses jwt-ssh-agent approach: direct JWT signing without wrapper structure.
// Follows standard SSH client behavior for key discovery and iteration.
func CreateSSHSignedJWT(config *Config) (signedJWT string, err error) {
	// Create unified SSH client that handles both agent and filesystem keys
	sshClient, err := NewUnifiedSSHClient(config)
	if err != nil {
		return "", fmt.Errorf("failed to create SSH client: %w", err)
	}

	// Get SSH keys from all sources (agent + filesystem)
	keys, err := sshClient.GetKeys()
	if err != nil {
		return "", fmt.Errorf("failed to get SSH keys: %w", err)
	}

	if len(keys) == 0 {
		return "", errors.New("no SSH keys available from agent or filesystem")
	}

	// Try each key in sequence until one succeeds (standard SSH behavior)
	var keyErrors []KeyAttemptError
	for i, sshKey := range keys {
		result, attemptErr := tryUnifiedKeyAuthentication(sshKey, config, sshClient)
		if attemptErr == nil {
			// Success! Return the signed JWT
			return result, nil
		}

		// Record this key's failure and try the next one
		keyErrors = append(keyErrors, KeyAttemptError{
			Index:       i,
			Fingerprint: sshKey.Fingerprint,
			Comment:     sshKey.Comment,
			Source:      sshKey.Source, // "agent" or filesystem path
			Error:       attemptErr,
		})
	}

	// All keys failed - return comprehensive error
	return "", NewMultiKeyAuthError(keyErrors)
}

// tryUnifiedKeyAuthentication attempts to create and sign a JWT with a unified SSH key.
// Uses jwt-ssh-agent approach: custom signing method with minimal claims.
func tryUnifiedKeyAuthentication(sshKey *SSHKey, config *Config, sshClient *UnifiedSSHClient) (string, error) {
	// Generate a unique JWT ID
	jwtID, err := generateJTI()
	if err != nil {
		return "", fmt.Errorf("failed to generate JWT ID: %w", err)
	}

	// Create JWT claims - minimal, standards-compliant approach like jwt-ssh-agent
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":             "kubectl-ssh-oidc",                             // Issuer
		"sub":             config.Username,                                // Subject (username)
		"aud":             config.Audience,                                // Audience
		"jti":             jwtID,                                          // JWT ID
		"exp":             now.Add(5 * time.Minute).Unix(),                // Expires in 5 minutes
		"iat":             now.Unix(),                                     // Issued at
		"nbf":             now.Unix(),                                     // Not before
		"key_fingerprint": sshKey.Fingerprint,                             // SSH key fingerprint for server lookup
		"public_key":      base64.StdEncoding.EncodeToString(sshKey.Blob), // For signature verification
	}

	// Create JWT with custom SSH signing method for unified keys
	token := jwt.NewWithClaims(&UnifiedSSHSigningMethod{
		sshClient: sshClient,
		sshKey:    sshKey,
	}, claims)

	// Sign the JWT directly with SSH key
	tokenString, err := token.SignedString(sshKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT with SSH key: %w", err)
	}

	return tokenString, nil
}

// UnifiedSSHSigningMethod implements JWT signing using unified SSH keys.
type UnifiedSSHSigningMethod struct {
	sshClient *UnifiedSSHClient
	sshKey    *SSHKey
}

// Alg returns the signing method algorithm identifier.
func (m *UnifiedSSHSigningMethod) Alg() string {
	return "SSH"
}

// Sign signs the JWT token string with the unified SSH key.
func (m *UnifiedSSHSigningMethod) Sign(signingString string, key any) ([]byte, error) {
	// Verify key is our expected SSH key
	sshKey, ok := key.(*SSHKey)
	if !ok {
		return nil, fmt.Errorf("unified SSH signing method requires *SSHKey, got %T", key)
	}

	// Sign the JWT token string using unified client
	signature, _, err := m.sshClient.SignWithKey(sshKey, []byte(signingString))
	if err != nil {
		return nil, fmt.Errorf("failed to sign with unified SSH key: %w", err)
	}

	// Return base64-encoded signature in SSH format
	return []byte(base64.StdEncoding.EncodeToString(signature.Blob)), nil
}

// Verify verifies the JWT signature using the SSH public key.
func (m *UnifiedSSHSigningMethod) Verify(signingString string, signature []byte, key any) error {
	// This would be implemented by the server (Dex) side
	return errors.New("SSH signature verification not implemented in client")
}

// KeyAttemptError represents a failed authentication attempt with a specific SSH key.
type KeyAttemptError struct {
	Index       int    // Key index in iteration order
	Fingerprint string // SSH key fingerprint
	Comment     string // SSH key comment
	Source      string // "agent" or filesystem path
	Error       error  // The error that occurred
}

// MultiKeyAuthError represents authentication failure with all available SSH keys.
type MultiKeyAuthError struct {
	KeyErrors []KeyAttemptError
}

// NewMultiKeyAuthError creates a new MultiKeyAuthError.
func NewMultiKeyAuthError(keyErrors []KeyAttemptError) *MultiKeyAuthError {
	return &MultiKeyAuthError{KeyErrors: keyErrors}
}

// Error implements the error interface for MultiKeyAuthError.
func (e *MultiKeyAuthError) Error() string {
	if len(e.KeyErrors) == 0 {
		return "authentication failed: no SSH keys attempted"
	}

	if len(e.KeyErrors) == 1 {
		return fmt.Sprintf("authentication failed with SSH key %s: %v",
			e.KeyErrors[0].Fingerprint, e.KeyErrors[0].Error)
	}

	// Multiple key failures - provide summary
	var errorLines []string
	errorLines = append(errorLines, fmt.Sprintf("authentication failed with all %d SSH keys:", len(e.KeyErrors)))

	for _, keyErr := range e.KeyErrors {
		comment := keyErr.Comment
		if comment == "" {
			comment = "(no comment)"
		}
		source := keyErr.Source
		if source == "" {
			source = "unknown"
		}
		errorLines = append(errorLines,
			fmt.Sprintf("  key %d (%s): %s %s - %v",
				keyErr.Index+1, source, keyErr.Fingerprint, comment, keyErr.Error))
	}

	errorLines = append(errorLines, "")
	errorLines = append(errorLines, "Possible solutions:")
	errorLines = append(errorLines, "  1. Ensure one of these keys is authorized in Dex configuration")
	errorLines = append(errorLines, "  2. Load an authorized key: ssh-add ~/.ssh/authorized_key")
	errorLines = append(errorLines, "  3. Check Dex logs for authorization details")

	return strings.Join(errorLines, "\n")
}

// ExchangeWithDex exchanges the SSH-signed JWT for an OIDC token from Dex.
// Uses direct token exchange - sends SSH JWT directly to token endpoint.
func ExchangeWithDex(config *Config, sshJWT string) (*DexTokenResponse, error) {
	err := validateJWT(sshJWT)
	if err != nil {
		return nil, err
	}

	baseURL := strings.TrimSuffix(config.DexURL, "/")
	tokenURL := baseURL + "/auth/ssh/token"

	// Create form data with SSH JWT
	formData := url.Values{
		"ssh_jwt": {sshJWT},
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, tokenURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	// Send request
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange with Dex: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}

	// Check for errors
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("SSH authentication failed (%d): %s", resp.StatusCode, string(respBody))
	}

	// Parse JSON response
	var tokenResp DexTokenResponse
	parseErr := json.Unmarshal(respBody, &tokenResp)
	if parseErr != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", parseErr)
	}

	return &tokenResp, nil
}

// validateJWT validates the format of the SSH JWT.
func validateJWT(sshJWT string) error {
	if !strings.Contains(sshJWT, ".") {
		return errors.New("authentication failed: invalid JWT format")
	}

	parts := strings.Split(sshJWT, ".")
	if len(parts) != 3 {
		return errors.New("authentication failed: malformed JWT")
	}

	return nil
}

// LoadConfig loads configuration from environment or default values.
func LoadConfig() *Config {
	config := &Config{
		DexURL:         getEnvOrDefault("DEX_URL", "https://dex.example.com"),
		ClientID:       getEnvOrDefault("CLIENT_ID", "kubectl-ssh-oidc"),
		ClientSecret:   getEnvOrDefault("CLIENT_SECRET", ""),
		Audience:       getEnvOrDefault("AUDIENCE", "kubernetes"),
		CacheTokens:    getEnvOrDefault("CACHE_TOKENS", trueString) == trueString,
		Username:       getEnvOrDefault("KUBECTL_SSH_USER", ""),
		UseAgent:       getEnvOrDefault("SSH_USE_AGENT", trueString) == trueString,
		IdentitiesOnly: getEnvOrDefault("SSH_IDENTITIES_ONLY", "false") == trueString,
	}

	// Parse custom SSH key paths from environment
	if keyPaths := os.Getenv("SSH_KEY_PATHS"); keyPaths != "" {
		config.SSHKeyPaths = strings.Split(keyPaths, ":")
	}

	// Parse command line args (skip flags like --debug)
	var positionalArgs []string
	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		if !strings.HasPrefix(arg, "-") {
			positionalArgs = append(positionalArgs, arg)
		}
	}

	// Override with positional command line args if provided
	if len(positionalArgs) > 0 {
		config.DexURL = positionalArgs[0]
	}
	if len(positionalArgs) > 1 {
		config.ClientID = positionalArgs[1]
	}
	if len(positionalArgs) > 2 {
		config.Username = positionalArgs[2]
	}

	// Username is required for proper JWT claims
	if config.Username == "" {
		config.Username = getSystemUsername()
	}

	return config
}

// getEnvOrDefault returns environment variable value or default.
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// generateJTI generates a unique JWT ID.
func generateJTI() (string, error) {
	bytes := make([]byte, 16)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// getSystemUsername returns the current system username.
func getSystemUsername() string {
	if user := os.Getenv("USER"); user != "" {
		return user
	}
	if user := os.Getenv("USERNAME"); user != "" {
		return user
	}
	return "unknown"
}

// OutputExecCredential outputs the kubectl exec credential.
func OutputExecCredential(token string, expiresIn int) error {
	// Calculate expiration time
	var expiration *metav1.Time
	if expiresIn > 0 {
		exp := time.Now().Add(time.Duration(expiresIn) * time.Second)
		expiration = &metav1.Time{Time: exp}
	}

	// Create exec credential
	cred := &clientauthv1beta1.ExecCredential{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "client.authentication.k8s.io/v1beta1",
			Kind:       "ExecCredential",
		},
		Status: &clientauthv1beta1.ExecCredentialStatus{
			Token:               token,
			ExpirationTimestamp: expiration,
		},
	}

	// Output as JSON
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(cred)
}
