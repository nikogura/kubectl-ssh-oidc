package ssh

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dexidp/dex/connector"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nikogura/kubectl-ssh-oidc/testdata"
)

func TestConfig_Open(t *testing.T) {
	config := &Config{
		Users: map[string]UserConfig{
			"testuser": {
				Keys: []string{"SHA256:test-fingerprint"},
				UserInfo: UserInfo{
					Username: "testuser",
					Email:    "test@example.com",
					Groups:   []string{"developers"},
					FullName: "Test User",
				},
			},
		},
		AllowedIssuers: []string{"test-issuer"},
		DefaultGroups:  []string{"authenticated"},
		TokenTTL:       3600,
	}

	conn, err := config.Open("test-id", nil)

	require.NoError(t, err)
	assert.NotNil(t, conn)
	assert.IsType(t, &SSHConnector{}, conn)
}

func TestSSHConnector_LoginURL(t *testing.T) {
	config := &Config{}
	conn, _ := config.Open("test", nil)
	sshConnector := conn.(*SSHConnector)

	scopes := connector.Scopes{}
	loginURL, err := sshConnector.LoginURL(scopes, "http://callback.example.com", "test-state")

	require.NoError(t, err)
	assert.Equal(t, "http://callback.example.com?state=test-state&ssh_auth=true", loginURL)
}

func TestSSHConnector_HandleCallback_NoJWT(t *testing.T) {
	config := &Config{}
	conn, _ := config.Open("test", nil)
	sshConnector := conn.(*SSHConnector)

	scopes := connector.Scopes{}
	req := httptest.NewRequest(http.MethodPost, "/callback", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	identity, err := sshConnector.HandleCallback(scopes, req)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no SSH JWT or authorization code provided")
	assert.Equal(t, connector.Identity{}, identity)
}

func TestSSHConnector_TokenURL(t *testing.T) {
	config := &Config{}
	conn, _ := config.Open("test", nil)
	sshConnector := conn.(*SSHConnector)

	url := sshConnector.TokenURL()
	assert.Equal(t, "/ssh/token", url)
}

func TestSSHConnector_verifySSHSignature(t *testing.T) {
	_, testSigner, testPubKeyBytes, err := testdata.GenerateTestSSHKey()
	require.NoError(t, err)

	config := &Config{}
	conn, _ := config.Open("test", nil)
	sshConnector := conn.(*SSHConnector)

	testData := "test data to verify"

	t.Run("valid signature", func(t *testing.T) {
		// Sign test data
		signature, signErr := testSigner.Sign(nil, []byte(testData))
		require.NoError(t, signErr)

		// Verify signature
		verifyErr := sshConnector.verifySSHSignature(
			testData,
			base64.StdEncoding.EncodeToString(signature.Blob),
			signature.Format,
			base64.StdEncoding.EncodeToString(testPubKeyBytes),
		)

		assert.NoError(t, verifyErr)
	})

	t.Run("invalid signature", func(t *testing.T) {
		// Use wrong signature
		invalidSignature := base64.StdEncoding.EncodeToString([]byte("invalid-signature"))

		verifyErr := sshConnector.verifySSHSignature(
			testData,
			invalidSignature,
			"rsa-sha2-256",
			base64.StdEncoding.EncodeToString(testPubKeyBytes),
		)

		require.Error(t, verifyErr)
		assert.Contains(t, verifyErr.Error(), "signature verification failed")
	})

	t.Run("invalid public key", func(t *testing.T) {
		invalidPubKey := base64.StdEncoding.EncodeToString([]byte("invalid-key"))

		err = sshConnector.verifySSHSignature(
			testData,
			"signature",
			"rsa-sha2-256",
			invalidPubKey,
		)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse public key")
	})
}

func TestSSHConnector_isAllowedIssuer(t *testing.T) {
	tests := []struct {
		name           string
		allowedIssuers []string
		testIssuer     string
		expected       bool
	}{
		{
			name:           "empty allowed issuers allows all",
			allowedIssuers: []string{},
			testIssuer:     "any-issuer",
			expected:       true,
		},
		{
			name:           "issuer in allowed list",
			allowedIssuers: []string{"issuer1", "issuer2"},
			testIssuer:     "issuer1",
			expected:       true,
		},
		{
			name:           "issuer not in allowed list",
			allowedIssuers: []string{"issuer1", "issuer2"},
			testIssuer:     "issuer3",
			expected:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{AllowedIssuers: tt.allowedIssuers}
			conn, _ := config.Open("test", nil)
			sshConnector := conn.(*SSHConnector)

			result := sshConnector.isAllowedIssuer(tt.testIssuer)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSSHConnector_SetSigningKeyFromInterface(t *testing.T) {
	t.Run("rsa_private_key", func(t *testing.T) {
		// Create fresh connector for this test
		config := &Config{}
		conn, err := config.Open("test", nil)
		require.NoError(t, err)
		sshConnector := conn.(*SSHConnector)
		// Test with direct RSA private key
		rsaKey, keyErr := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, keyErr)

		setErr := sshConnector.SetSigningKeyFromInterface(rsaKey)
		require.NoError(t, setErr)
		require.Len(t, sshConnector.signingKeys, 1)
		assert.Equal(t, rsaKey, sshConnector.signingKeys[0])
	})

	t.Run("jose_json_web_key", func(t *testing.T) {
		// Create fresh connector for this test
		config := &Config{}
		conn, err := config.Open("test", nil)
		require.NoError(t, err)
		sshConnector := conn.(*SSHConnector)

		// Test with JOSE JSONWebKey containing RSA key
		rsaKey, keyErr := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, keyErr)

		joseKey := &jose.JSONWebKey{
			Key: rsaKey,
		}

		setErr := sshConnector.SetSigningKeyFromInterface(joseKey)
		require.NoError(t, setErr)
		require.Len(t, sshConnector.signingKeys, 1)
		assert.Equal(t, rsaKey, sshConnector.signingKeys[0])
	})

	t.Run("jose_with_unsupported_key", func(t *testing.T) {
		// Create fresh connector for this test
		config := &Config{}
		conn, err := config.Open("test", nil)
		require.NoError(t, err)
		sshConnector := conn.(*SSHConnector)

		// Test with JOSE JSONWebKey containing non-RSA key
		joseKey := &jose.JSONWebKey{
			Key: "not-an-rsa-key",
		}

		setErr := sshConnector.SetSigningKeyFromInterface(joseKey)
		require.Error(t, setErr)
		assert.Contains(t, setErr.Error(), "JSONWebKey does not contain RSA private key")
	})

	t.Run("unsupported_type", func(t *testing.T) {
		// Create fresh connector for this test
		config := &Config{}
		conn, err := config.Open("test", nil)
		require.NoError(t, err)
		sshConnector := conn.(*SSHConnector)

		// Test with unsupported key type
		setErr := sshConnector.SetSigningKeyFromInterface("unsupported-type")
		require.Error(t, setErr)
		assert.Contains(t, setErr.Error(), "unsupported key type: string")
	})
}
