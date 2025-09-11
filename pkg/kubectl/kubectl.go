package kubectl

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
)

// Config represents the plugin configuration.
type Config struct {
	DexURL      string `json:"dex_url"`
	ClientID    string `json:"client_id"`
	Audience    string `json:"audience"`
	CacheTokens bool   `json:"cache_tokens"`
}

// SSHJWTClaims represents JWT claims for SSH authentication.
type SSHJWTClaims struct {
	jwt.RegisteredClaims
	KeyFingerprint string `json:"key_fingerprint"`
	KeyComment     string `json:"key_comment,omitempty"`
	PublicKey      string `json:"public_key"`
}

// DexTokenResponse represents the response from Dex token endpoint.
type DexTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

// SSHAgentClientInterface defines the SSH agent client interface.
type SSHAgentClientInterface interface {
	GetKeys() ([]*agent.Key, error)
	SignData(data []byte) (*ssh.Signature, ssh.PublicKey, error)
	SignWithKey(key *agent.Key, data []byte) (*ssh.Signature, ssh.PublicKey, error)
}

// SSHAgentClient wraps SSH agent functionality.
type SSHAgentClient struct {
	agent agent.ExtendedAgent
}

// NewSSHAgentClient creates a new SSH agent client.
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

// CreateSSHSignedJWT creates a JWT signed with an SSH key from the agent.
// Follows standard SSH client behavior by trying each key until one succeeds.
func CreateSSHSignedJWT(config *Config) (signedJWT string, err error) {
	sshClient, err := NewSSHAgentClient()
	if err != nil {
		return "", err
	}

	// Get SSH keys from agent
	keys, err := sshClient.GetKeys()
	if err != nil {
		return "", err
	}

	if len(keys) == 0 {
		return "", errors.New("no SSH keys available in agent")
	}

	// Try each key in sequence until one succeeds (standard SSH behavior)
	var keyErrors []KeyAttemptError
	for i, sshKey := range keys {
		result, attemptErr := tryKeyAuthentication(sshKey, config, sshClient)
		if attemptErr == nil {
			// Success! Return the signed JWT
			return result, nil
		}

		// Record this key's failure and try the next one
		pubKey, parseErr := ssh.ParsePublicKey(sshKey.Blob)
		fingerprint := "<invalid>"
		if parseErr == nil {
			fingerprint = ssh.FingerprintSHA256(pubKey)
		}

		keyErrors = append(keyErrors, KeyAttemptError{
			Index:       i,
			Fingerprint: fingerprint,
			Comment:     sshKey.Comment,
			Error:       attemptErr,
		})
	}

	// All keys failed - return comprehensive error
	return "", NewMultiKeyAuthError(keyErrors)
}

// tryKeyAuthentication attempts to create and sign a JWT with a specific SSH key.
func tryKeyAuthentication(sshKey *agent.Key, config *Config, sshClient SSHAgentClientInterface) (string, error) {
	// Parse the public key
	pubKey, err := ssh.ParsePublicKey(sshKey.Blob)
	if err != nil {
		return "", fmt.Errorf("failed to parse public key: %w", err)
	}

	// Generate key fingerprint
	fingerprint := ssh.FingerprintSHA256(pubKey)

	// Create JWT claims with this specific key
	now := time.Now()
	claims := &SSHJWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "kubectl-ssh-oidc",
			Audience:  jwt.ClaimStrings{config.Audience},
			Subject:   fingerprint,
			ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
		KeyFingerprint: fingerprint,
		KeyComment:     sshKey.Comment,
		PublicKey:      base64.StdEncoding.EncodeToString(sshKey.Blob),
	}

	// Create unsigned token
	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		return "", fmt.Errorf("failed to create token: %w", err)
	}

	// Sign the token with this specific SSH key
	tokenBytes := []byte(tokenString)
	signature, _, err := sshClient.SignWithKey(sshKey, tokenBytes)
	if err != nil {
		return "", fmt.Errorf("failed to sign with SSH key: %w", err)
	}

	// Create final JWT with SSH signature
	signedToken := &SSHSignedJWT{
		Token:     tokenString,
		Signature: base64.StdEncoding.EncodeToString(signature.Blob),
		Format:    signature.Format,
	}

	signedTokenBytes, err := json.Marshal(signedToken)
	if err != nil {
		return "", fmt.Errorf("failed to marshal signed token: %w", err)
	}

	return base64.StdEncoding.EncodeToString(signedTokenBytes), nil
}

// SSHSignedJWT represents a JWT signed with SSH key.
type SSHSignedJWT struct {
	Token     string `json:"token"`
	Signature string `json:"signature"`
	Format    string `json:"format"`
}

// KeyAttemptError represents a failed authentication attempt with a specific SSH key.
type KeyAttemptError struct {
	Index       int    // Key index in agent
	Fingerprint string // SSH key fingerprint
	Comment     string // SSH key comment
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
		errorLines = append(errorLines,
			fmt.Sprintf("  key %d: %s %s - %v",
				keyErr.Index+1, keyErr.Fingerprint, comment, keyErr.Error))
	}

	errorLines = append(errorLines, "")
	errorLines = append(errorLines, "Possible solutions:")
	errorLines = append(errorLines, "  1. Ensure one of these keys is authorized in Dex configuration")
	errorLines = append(errorLines, "  2. Load an authorized key: ssh-add ~/.ssh/authorized_key")
	errorLines = append(errorLines, "  3. Check Dex logs for authorization details")

	return strings.Join(errorLines, "\n")
}

// ExchangeWithDex exchanges the SSH-signed JWT for an OIDC token from Dex.
func ExchangeWithDex(config *Config, sshJWT string) (*DexTokenResponse, error) {
	// Custom token endpoint for SSH JWT exchange
	tokenURL := fmt.Sprintf("%s/token", config.DexURL)

	// Prepare form data
	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	data.Set("assertion", sshJWT)
	data.Set("client_id", config.ClientID)
	data.Set("scope", "openid profile email groups")

	// Make request to Dex
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, tokenURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.PostForm = data

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to request token from Dex: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse token response
	var tokenResp DexTokenResponse
	parseErr := json.Unmarshal(body, &tokenResp)
	if parseErr != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", parseErr)
	}

	return &tokenResp, nil
}

// LoadConfig loads configuration from environment or default values.
func LoadConfig() *Config {
	config := &Config{
		DexURL:      getEnvOrDefault("DEX_URL", "https://dex.example.com"),
		ClientID:    getEnvOrDefault("CLIENT_ID", "kubectl-ssh-oidc"),
		Audience:    getEnvOrDefault("AUDIENCE", "kubernetes"),
		CacheTokens: getEnvOrDefault("CACHE_TOKENS", "true") == "true",
	}

	// Override with command line args if provided
	if len(os.Args) > 1 {
		config.DexURL = os.Args[1]
	}
	if len(os.Args) > 2 {
		config.ClientID = os.Args[2]
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
