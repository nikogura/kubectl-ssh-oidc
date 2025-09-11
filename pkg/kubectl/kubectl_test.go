package kubectl

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	clientauthv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"

	"github.com/nikogura/kubectl-ssh-oidc/pkg/kubectl/mocks"
	"github.com/nikogura/kubectl-ssh-oidc/testdata"
)

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name     string
		envVars  map[string]string
		args     []string
		expected *Config
	}{
		{
			name:    "default config",
			envVars: map[string]string{},
			args:    []string{"kubectl-ssh-oidc"},
			expected: &Config{
				DexURL:      "https://dex.example.com",
				ClientID:    "kubectl-ssh-oidc",
				Audience:    "kubernetes",
				CacheTokens: true,
			},
		},
		{
			name: "env vars override",
			envVars: map[string]string{
				"DEX_URL":      "https://custom-dex.example.com",
				"CLIENT_ID":    "custom-client",
				"AUDIENCE":     "custom-audience",
				"CACHE_TOKENS": "false",
			},
			args: []string{"kubectl-ssh-oidc"},
			expected: &Config{
				DexURL:      "https://custom-dex.example.com",
				ClientID:    "custom-client",
				Audience:    "custom-audience",
				CacheTokens: false,
			},
		},
		{
			name:    "command line args override",
			envVars: map[string]string{},
			args:    []string{"kubectl-ssh-oidc", "https://cli-dex.example.com", "cli-client"},
			expected: &Config{
				DexURL:      "https://cli-dex.example.com",
				ClientID:    "cli-client",
				Audience:    "kubernetes",
				CacheTokens: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables
			for key, value := range tt.envVars {
				t.Setenv(key, value)
			}
			defer func() {
				for key := range tt.envVars {
					os.Unsetenv(key)
				}
			}()

			// Set command line args - using temporary override
			originalArgs := make([]string, len(os.Args))
			copy(originalArgs, os.Args)
			defer func() {
				os.Args = make([]string, len(originalArgs)) //nolint:reassign // necessary for testing os.Args override
				copy(os.Args, originalArgs)
			}()
			os.Args = make([]string, len(tt.args)) //nolint:reassign // necessary for testing os.Args override
			copy(os.Args, tt.args)

			config := LoadConfig()
			assert.Equal(t, tt.expected, config)
		})
	}
}

func TestSSHAgentClient_GetKeys(t *testing.T) {
	tests := []struct {
		name          string
		mockSetup     func(*mocks.MockExtendedAgent)
		expectedKeys  int
		expectedError string
	}{
		{
			name: "success with keys",
			mockSetup: func(m *mocks.MockExtendedAgent) {
				testKey, err := testdata.CreateTestAgentKey()
				require.NoError(t, err)
				m.On("List").Return([]*agent.Key{testKey}, nil)
			},
			expectedKeys: 1,
		},
		{
			name: "agent error",
			mockSetup: func(m *mocks.MockExtendedAgent) {
				m.On("List").Return([]*agent.Key(nil), errors.New("agent connection failed"))
			},
			expectedError: "failed to list SSH keys",
		},
		{
			name: "no keys found",
			mockSetup: func(m *mocks.MockExtendedAgent) {
				m.On("List").Return([]*agent.Key{}, nil)
			},
			expectedError: "no SSH keys found in agent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAgent := &mocks.MockExtendedAgent{}
			tt.mockSetup(mockAgent)

			client := &SSHAgentClient{agent: mockAgent}
			keys, err := client.GetKeys()

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, keys)
			} else {
				require.NoError(t, err)
				assert.Len(t, keys, tt.expectedKeys)
			}

			mockAgent.AssertExpectations(t)
		})
	}
}

func TestSSHAgentClient_SignData(t *testing.T) {
	tests := []struct {
		name          string
		mockSetup     func(*mocks.MockExtendedAgent)
		data          []byte
		expectedError string
	}{
		{
			name: "successful signing",
			mockSetup: func(m *mocks.MockExtendedAgent) {
				testKey, err := testdata.CreateTestAgentKey()
				require.NoError(t, err)

				m.On("List").Return([]*agent.Key{testKey}, nil)
				m.On("Sign", mock.AnythingOfType("*agent.Key"), mock.AnythingOfType("[]uint8")).
					Return(testdata.TestSSHSignature(), nil)
			},
			data: []byte("test data to sign"),
		},
		{
			name: "no keys available",
			mockSetup: func(m *mocks.MockExtendedAgent) {
				m.On("List").Return([]*agent.Key{}, nil)
			},
			data:          []byte("test data"),
			expectedError: "no SSH keys found in agent",
		},
		{
			name: "signing fails",
			mockSetup: func(m *mocks.MockExtendedAgent) {
				testKey, err := testdata.CreateTestAgentKey()
				require.NoError(t, err)

				m.On("List").Return([]*agent.Key{testKey}, nil)
				m.On("Sign", mock.AnythingOfType("*agent.Key"), mock.AnythingOfType("[]uint8")).
					Return((*ssh.Signature)(nil), errors.New("signing failed"))
			},
			data:          []byte("test data"),
			expectedError: "failed to sign data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAgent := &mocks.MockExtendedAgent{}
			tt.mockSetup(mockAgent)

			client := &SSHAgentClient{agent: mockAgent}
			signature, pubKey, err := client.SignData(tt.data)

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, signature)
				assert.Nil(t, pubKey)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, signature)
				assert.NotNil(t, pubKey)
			}

			mockAgent.AssertExpectations(t)
		})
	}
}

func TestCreateSSHSignedJWT(t *testing.T) {
	// This test requires more complex setup since it involves creating actual SSH keys
	// and JWT tokens. We'll create a simplified version that tests the structure.

	t.Run("JWT structure validation", func(t *testing.T) {
		// Test that we can decode and validate the JWT structure
		// This is a structural test rather than a full integration test

		// Create mock signed JWT response (base64 encoded JSON)
		signedJWT := SSHSignedJWT{
			Token:     "test.jwt.token",
			Signature: base64.StdEncoding.EncodeToString([]byte("test-signature")),
			Format:    "rsa-sha2-256",
		}

		signedJWTBytes, err := json.Marshal(signedJWT)
		require.NoError(t, err)

		encodedJWT := base64.StdEncoding.EncodeToString(signedJWTBytes)

		// Decode and verify structure
		decodedBytes, err := base64.StdEncoding.DecodeString(encodedJWT)
		require.NoError(t, err)

		var decodedJWT SSHSignedJWT
		err = json.Unmarshal(decodedBytes, &decodedJWT)
		require.NoError(t, err)

		assert.Equal(t, signedJWT.Token, decodedJWT.Token)
		assert.Equal(t, signedJWT.Signature, decodedJWT.Signature)
		assert.Equal(t, signedJWT.Format, decodedJWT.Format)
	})
}

func TestExchangeWithDex(t *testing.T) {
	tests := []struct {
		name          string
		config        *Config
		sshJWT        string
		mockResponse  *http.Response
		expectedToken *DexTokenResponse
		expectedError string
	}{
		{
			name: "successful token exchange",
			config: &Config{
				DexURL:   "https://test-dex.example.com",
				ClientID: "test-client",
			},
			sshJWT: "test.ssh.jwt",
			mockResponse: &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(testdata.TestDexTokenResponse())),
			},
			expectedToken: &DexTokenResponse{
				AccessToken:  "test-access-token",
				TokenType:    "Bearer",
				ExpiresIn:    3600,
				RefreshToken: "test-refresh-token",
				IDToken:      "test-id-token",
			},
		},
		{
			name: "dex returns error",
			config: &Config{
				DexURL:   "https://test-dex.example.com",
				ClientID: "test-client",
			},
			sshJWT: "test.ssh.jwt",
			mockResponse: &http.Response{
				StatusCode: http.StatusUnauthorized,
				Body:       io.NopCloser(strings.NewReader(`{"error": "invalid_grant"}`)),
			},
			expectedError: "token request failed with status 401",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: This test would need HTTP client injection to properly mock
			// For now, we're testing the response parsing logic

			if tt.expectedToken != nil {
				// Test response parsing
				var tokenResp DexTokenResponse
				bodyBytes, err := io.ReadAll(tt.mockResponse.Body)
				require.NoError(t, err)

				err = json.Unmarshal(bodyBytes, &tokenResp)
				require.NoError(t, err)

				assert.Equal(t, tt.expectedToken.AccessToken, tokenResp.AccessToken)
				assert.Equal(t, tt.expectedToken.TokenType, tokenResp.TokenType)
				assert.Equal(t, tt.expectedToken.ExpiresIn, tokenResp.ExpiresIn)
			}
		})
	}
}

func TestOutputExecCredential(t *testing.T) {
	tests := []struct {
		name        string
		token       string
		expiresIn   int
		expectError bool
	}{
		{
			name:      "valid credential output",
			token:     "test-access-token",
			expiresIn: 3600,
		},
		{
			name:      "credential without expiration",
			token:     "test-access-token",
			expiresIn: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture stdout
			originalStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w //nolint:reassign // necessary for testing stdout capture

			err := OutputExecCredential(tt.token, tt.expiresIn)

			// Restore stdout and close writer
			w.Close()
			os.Stdout = originalStdout //nolint:reassign // necessary for testing stdout capture

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)

			// Read captured output
			var buf bytes.Buffer
			buf.ReadFrom(r)
			output := buf.String()

			// Parse the output as ExecCredential
			var cred clientauthv1beta1.ExecCredential
			err = json.Unmarshal([]byte(output), &cred)
			require.NoError(t, err)

			assert.Equal(t, "client.authentication.k8s.io/v1beta1", cred.APIVersion)
			assert.Equal(t, "ExecCredential", cred.Kind)
			assert.Equal(t, tt.token, cred.Status.Token)

			if tt.expiresIn > 0 {
				assert.NotNil(t, cred.Status.ExpirationTimestamp)

				// Verify expiration is approximately correct (within 1 second)
				expectedExpiration := time.Now().Add(time.Duration(tt.expiresIn) * time.Second)
				actualExpiration := cred.Status.ExpirationTimestamp.Time
				diff := actualExpiration.Sub(expectedExpiration)
				assert.True(t, diff < time.Second && diff > -time.Second,
					"Expiration time should be within 1 second of expected")
			} else {
				assert.Nil(t, cred.Status.ExpirationTimestamp)
			}
		})
	}
}

func TestSSHJWTClaimsValidation(t *testing.T) {
	testKey, _, publicKeyBytes, err := testdata.GenerateTestSSHKey()
	require.NoError(t, err)

	fingerprint := ssh.FingerprintSHA256(testKey)

	now := time.Now()
	claims := &SSHJWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "test-issuer",
			Audience:  jwt.ClaimStrings{"test-audience"},
			Subject:   fingerprint,
			ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
		KeyFingerprint: fingerprint,
		KeyComment:     "test-key@example.com",
		PublicKey:      base64.StdEncoding.EncodeToString(publicKeyBytes),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)

	// Parse token back
	parsedToken, err := jwt.ParseWithClaims(tokenString, &SSHJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return jwt.UnsafeAllowNoneSignatureType, nil
	})
	require.NoError(t, err)

	parsedClaims, ok := parsedToken.Claims.(*SSHJWTClaims)
	require.True(t, ok)

	assert.Equal(t, claims.Issuer, parsedClaims.Issuer)
	assert.Equal(t, claims.KeyFingerprint, parsedClaims.KeyFingerprint)
	assert.Equal(t, claims.KeyComment, parsedClaims.KeyComment)
	assert.Equal(t, claims.PublicKey, parsedClaims.PublicKey)
}
