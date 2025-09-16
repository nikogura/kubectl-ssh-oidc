//go:build integration
// +build integration

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	clientauthv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"

	"github.com/nikogura/kubectl-ssh-oidc/pkg/kubectl"
	"github.com/nikogura/kubectl-ssh-oidc/pkg/ssh"
)

// TestEndToEndFlow tests the complete flow from SSH JWT creation to Dex token exchange.
// This requires a running SSH agent with keys loaded.
func TestEndToEndFlow(t *testing.T) {
	// Skip if SSH_AUTH_SOCK is not set
	if os.Getenv("SSH_AUTH_SOCK") == "" {
		t.Skip("SSH_AUTH_SOCK not set, skipping integration test")
	}

	// Create a mock Dex server
	dexServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			// Mock Dex token response
			response := kubectl.DexTokenResponse{
				AccessToken:  "integration-test-access-token",
				TokenType:    "Bearer",
				ExpiresIn:    3600,
				RefreshToken: "integration-test-refresh-token",
				IDToken:      "integration-test-id-token",
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer dexServer.Close()

	// Test configuration
	config := &kubectl.Config{
		DexURL:      dexServer.URL,
		ClientID:    "integration-test-client",
		Audience:    "integration-test-audience",
		CacheTokens: false,
	}

	t.Run("SSH JWT creation", func(t *testing.T) {
		// This will only work if SSH agent has keys loaded
		sshJWT, err := kubectl.CreateSSHSignedJWT(config)

		if err != nil {
			t.Logf("SSH JWT creation failed (expected if no SSH agent): %v", err)
			t.Skip("SSH agent not available or no keys loaded")
		}

		assert.NotEmpty(t, sshJWT)
	})

	t.Run("Token exchange with mock Dex", func(t *testing.T) {
		// Use a mock JWT for token exchange test
		mockJWT := "mock-ssh-jwt-token"

		tokenResp, err := kubectl.ExchangeWithDex(config, mockJWT)
		require.NoError(t, err)

		assert.Equal(t, "integration-test-access-token", tokenResp.AccessToken)
		assert.Equal(t, "Bearer", tokenResp.TokenType)
		assert.Equal(t, 3600, tokenResp.ExpiresIn)
	})
}

func TestSSHConnectorIntegration(t *testing.T) {
	// Test SSH connector configuration
	config := &ssh.Config{
		AuthorizedKeys: map[string]ssh.UserInfo{
			"SHA256:integration-test-fingerprint": {
				Username: "integrationuser",
				Email:    "integration@example.com",
				Groups:   []string{"integration-test"},
				FullName: "Integration Test User",
			},
		},
		AllowedIssuers: []string{"kubectl-ssh-oidc"},
		DefaultGroups:  []string{"authenticated"},
		TokenTTL:       3600,
	}

	connector, err := config.Open("integration-test", nil)
	require.NoError(t, err)

	sshConnector, ok := connector.(*ssh.SSHConnector)
	require.True(t, ok)

	t.Run("LoginURL generation", func(t *testing.T) {
		scopes := ssh.Scopes{}
		loginURL, err := sshConnector.LoginURL(scopes, "http://callback.example.com", "integration-state")

		require.NoError(t, err)
		assert.Contains(t, loginURL, "ssh_auth=true")
		assert.Contains(t, loginURL, "integration-state")
	})

	t.Run("Token URL", func(t *testing.T) {
		tokenURL := sshConnector.TokenURL()
		assert.Equal(t, "/ssh/token", tokenURL)
	})
}

func TestKubectlExecCredentialOutput(t *testing.T) {
	// Test the kubectl exec credential output format
	testToken := "integration-test-kubectl-token"
	testExpiresIn := 7200

	// Capture output to validate format
	err := kubectl.OutputExecCredential(testToken, testExpiresIn)
	require.NoError(t, err)

	// Note: In a real integration test, we would capture stdout and parse it
	// This validates that the function runs without error with integration data
}

func TestConfigurationValidation(t *testing.T) {
	// Test that configuration loading works with different environment setups
	testCases := []struct {
		name     string
		envVars  map[string]string
		expected kubectl.Config
	}{
		{
			name: "integration environment",
			envVars: map[string]string{
				"DEX_URL":      "https://integration-dex.example.com",
				"CLIENT_ID":    "integration-client",
				"AUDIENCE":     "integration-audience",
				"CACHE_TOKENS": "false",
			},
			expected: kubectl.Config{
				DexURL:      "https://integration-dex.example.com",
				ClientID:    "integration-client",
				Audience:    "integration-audience",
				CacheTokens: false,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Set environment variables
			for key, value := range tc.envVars {
				os.Setenv(key, value)
			}
			defer func() {
				for key := range tc.envVars {
					os.Unsetenv(key)
				}
			}()

			config := kubectl.LoadConfig()
			assert.Equal(t, tc.expected.DexURL, config.DexURL)
			assert.Equal(t, tc.expected.ClientID, config.ClientID)
			assert.Equal(t, tc.expected.Audience, config.Audience)
			assert.Equal(t, tc.expected.CacheTokens, config.CacheTokens)
		})
	}
}

// TestRealSSHFlow tests with actual SSH agent if available.
// This test will be skipped if SSH agent is not running or has no keys.
func TestRealSSHFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping real SSH flow test in short mode")
	}

	// Check for SSH agent
	if os.Getenv("SSH_AUTH_SOCK") == "" {
		t.Skip("SSH_AUTH_SOCK not set")
	}

	// Try to create SSH client
	sshClient, err := kubectl.NewSSHAgentClient()
	if err != nil {
		t.Skipf("Cannot connect to SSH agent: %v", err)
	}

	// Try to get keys
	keys, err := sshClient.GetKeys()
	if err != nil {
		t.Skipf("Cannot get SSH keys: %v", err)
	}

	if len(keys) == 0 {
		t.Skip("No SSH keys in agent")
	}

	t.Run("SSH agent connectivity", func(t *testing.T) {
		assert.NotEmpty(t, keys)
		t.Logf("Found %d SSH keys in agent", len(keys))

		for i, key := range keys {
			t.Logf("Key %d: %s (%s)", i+1, key.Comment, key.Format)
		}
	})

	t.Run("SSH signing capability", func(t *testing.T) {
		testData := []byte("integration test data")

		signature, pubKey, err := sshClient.SignData(testData)
		require.NoError(t, err)
		assert.NotNil(t, signature)
		assert.NotNil(t, pubKey)

		t.Logf("Successfully signed data with key type: %s", pubKey.Type())
	})
}
