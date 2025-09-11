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

	// Use the first available key
	sshKey := keys[0]
	pubKey, err := ssh.ParsePublicKey(sshKey.Blob)
	if err != nil {
		return "", fmt.Errorf("failed to parse public key: %w", err)
	}

	// Generate key fingerprint
	fingerprint := ssh.FingerprintSHA256(pubKey)

	// Create JWT claims
	now := time.Now()
	claims := &SSHJWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "kubectl-ssh-oidc",
			Audience:  jwt.ClaimStrings{config.Audience},
			Subject:   fingerprint, // Use SSH key fingerprint as subject
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

	// Sign the token with SSH key
	tokenBytes := []byte(tokenString)
	signature, _, err := sshClient.SignData(tokenBytes)
	if err != nil {
		return "", err
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

	signedJWT = base64.StdEncoding.EncodeToString(signedTokenBytes)
	return signedJWT, nil
}

// SSHSignedJWT represents a JWT signed with SSH key.
type SSHSignedJWT struct {
	Token     string `json:"token"`
	Signature string `json:"signature"`
	Format    string `json:"format"`
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
