// Test client for kubectl-ssh-oidc authentication flow
// This demonstrates how to use OAuth2 Token Exchange with SSH keys

package main

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
	"golang.org/x/crypto/ssh/agent"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <dex-url> <username>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: %s https://dex.example.com username\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Note: Uses SSH agent for key access. Ensure ssh-agent is running and key is loaded.\n")
		os.Exit(1)
	}

	dexURL := os.Args[1]
	username := os.Args[2]

	fmt.Printf("Testing kubectl-ssh-oidc authentication\n")
	fmt.Printf("===================================\n")
	fmt.Printf("Dex URL: %s\n", dexURL)
	fmt.Printf("Username: %s\n", username)
	fmt.Printf("SSH Agent: $SSH_AUTH_SOCK = %s\n", os.Getenv("SSH_AUTH_SOCK"))
	fmt.Printf("\n")

	// Step 1: Create SSH-signed JWT using SSH agent
	fmt.Printf("1. Creating SSH-signed JWT using SSH agent...\n")
	sshJWT, err := createSSHJWTFromAgent(username)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create SSH JWT: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   ✅ SSH JWT created\n\n")

	// Step 2: Exchange SSH JWT for OIDC tokens using OAuth2 Token Exchange
	fmt.Printf("2. Exchanging SSH JWT via OAuth2 Token Exchange...\n")
	accessToken, idToken, err := exchangeTokens(dexURL, sshJWT)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Token exchange failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   ✅ Token exchange successful\n\n")

	// Step 3: Display results
	fmt.Printf("3. Results:\n")
	if len(accessToken) > 50 {
		fmt.Printf("   Access Token: %s...\n", accessToken[:50])
	} else {
		fmt.Printf("   Access Token: %s\n", accessToken)
	}
	if len(idToken) > 50 {
		fmt.Printf("   ID Token: %s...\n", idToken[:50])
	} else {
		fmt.Printf("   ID Token: %s\n", idToken)
	}
	fmt.Printf("\n")

	// Step 4: Validate ID token structure
	fmt.Printf("4. Validating ID token structure:\n")
	validationErr := validateIDToken(idToken)
	if validationErr != nil {
		fmt.Fprintf(os.Stderr, "ID token validation failed: %v\n", validationErr)
		os.Exit(1)
	}
	fmt.Printf("   ✅ ID token is valid for Kubernetes\n")

	fmt.Printf("\n🎉 kubectl-ssh-oidc authentication test successful!\n")
}

func createSSHJWTFromAgent(username string) (string, error) {
	// Connect to SSH agent
	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		return "", errors.New("SSH_AUTH_SOCK not set - is ssh-agent running?")
	}

	conn, err := (&net.Dialer{}).DialContext(context.Background(), "unix", socket)
	if err != nil {
		return "", fmt.Errorf("failed to connect to SSH agent: %w", err)
	}
	defer conn.Close()

	agentClient := agent.NewClient(conn)

	// List available keys
	keys, err := agentClient.List()
	if err != nil {
		return "", fmt.Errorf("failed to list SSH agent keys: %w", err)
	}

	if len(keys) == 0 {
		return "", errors.New("no keys available in SSH agent")
	}

	// Find the ED25519 key that's authorized for the user
	var key *agent.Key
	for _, k := range keys {
		if k.Type() == "ssh-ed25519" {
			key = k
			break
		}
	}
	if key == nil {
		return "", errors.New("no ED25519 key found in SSH agent")
	}
	fmt.Printf("   Using SSH key: %s (%s)\n", key.Comment, key.Type())

	// Note: public key and fingerprint no longer embedded in JWT for security

	// Create JWT claims
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": "kubectl-ssh-oidc",
		"sub": username,
		"aud": "kubernetes",
		"jti": fmt.Sprintf("%d-%s", now.UnixNano(), username),
		"exp": now.Add(5 * time.Minute).Unix(),
		"iat": now.Unix(),
		"nbf": now.Unix(),
	}

	// Create JWT with SSH agent signing
	token := jwt.NewWithClaims(&SSHAgentSigningMethod{agent: agentClient, key: key}, claims)
	return token.SignedString(key)
}

// SSHAgentSigningMethod implements JWT signing with SSH agent.
type SSHAgentSigningMethod struct {
	agent agent.Agent
	key   *agent.Key
}

func (m *SSHAgentSigningMethod) Alg() string {
	return "SSH"
}

func (m *SSHAgentSigningMethod) Sign(signingString string, key interface{}) ([]byte, error) {
	agentKey, ok := key.(*agent.Key)
	if !ok {
		return nil, fmt.Errorf("SSH agent signing method requires *agent.Key, got %T", key)
	}

	signature, err := m.agent.Sign(agentKey, []byte(signingString))
	if err != nil {
		return nil, fmt.Errorf("failed to sign with SSH agent: %w", err)
	}

	return []byte(base64.StdEncoding.EncodeToString(signature.Blob)), nil
}

func (m *SSHAgentSigningMethod) Verify(signingString string, signature []byte, key interface{}) error {
	return errors.New("SSH verification not implemented in client")
}

func exchangeTokens(dexURL, sshJWT string) (string, string, error) {
	// Prepare OAuth2 Token Exchange request
	data := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"subject_token":      {sshJWT},
		"connector_id":       {"ssh"}, // Required by Dex (not in RFC)
		"client_id":          {"0a934e2005af4386eed73f16931056"},
		"client_secret":      {"41192cdea4d706e945dc8765f6ed27"},
	}

	// Make token exchange request to Dex OAuth2 token endpoint
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, dexURL+"/token", strings.NewReader(data.Encode()))
	if err != nil {
		return "", "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("token exchange failed (status %d): %s", resp.StatusCode, string(body))
	}

	// Parse response
	var tokenResponse struct {
		AccessToken     string `json:"access_token"`
		IDToken         string `json:"id_token"`
		TokenType       string `json:"token_type"`
		ExpiresIn       int    `json:"expires_in"`
		IssuedTokenType string `json:"issued_token_type"`
	}

	unmarshalErr := json.Unmarshal(body, &tokenResponse)
	if unmarshalErr != nil {
		return "", "", fmt.Errorf("failed to parse token response: %w", unmarshalErr)
	}

	return tokenResponse.AccessToken, tokenResponse.IDToken, nil
}

func validateIDToken(tokenString string) error {
	// Parse JWT without validation (just to check structure)
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return fmt.Errorf("failed to parse ID token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return errors.New("invalid token claims")
	}

	// Check required Kubernetes OIDC claims
	requiredClaims := []string{"sub", "iss", "aud", "exp", "iat", "email", "groups"}
	for _, claim := range requiredClaims {
		if _, exists := claims[claim]; !exists {
			return fmt.Errorf("missing required claim: %s", claim)
		}
	}

	// Check algorithm
	if alg, algOK := token.Header["alg"]; !algOK || alg != "RS256" {
		return fmt.Errorf("expected RS256 algorithm, got: %v", token.Header["alg"])
	}

	// Check that 'typ' header is not present (matches Dex behavior)
	if _, hasTyp := token.Header["typ"]; hasTyp {
		return errors.New("unexpected 'typ' header present")
	}

	fmt.Printf("     - Algorithm: %s ✅\n", token.Header["alg"])
	fmt.Printf("     - Subject: %s ✅\n", claims["sub"])
	fmt.Printf("     - Issuer: %s ✅\n", claims["iss"])
	fmt.Printf("     - Audience: %s ✅\n", claims["aud"])
	fmt.Printf("     - Groups: %v ✅\n", claims["groups"])
	fmt.Printf("     - Email: %s ✅\n", claims["email"])

	return nil
}
