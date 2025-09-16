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

func TestSSHConnector_isKeyMatch(t *testing.T) {
	config := &Config{}
	conn, err := config.Open("test", nil)
	require.NoError(t, err)
	sshConnector := conn.(*SSHConnector)

	// Generate a test SSH key
	testKeys, err := testdata.GenerateSSHKeysForTest()
	require.NoError(t, err)
	require.Len(t, testKeys, 3)

	// Get the first key for testing
	testKey := testKeys[0]
	expectedFingerprint := testKey.Fingerprint

	// Test public key content (should be in ssh-ed25519 AAAAC3... format)
	publicKeyContent := string(testKey.PublicKeyBytes)

	t.Run("fingerprint_format_exact_match", func(t *testing.T) {
		// Test exact fingerprint match
		result := sshConnector.isKeyMatch(expectedFingerprint, expectedFingerprint)
		assert.True(t, result, "Fingerprint should match itself")
	})

	t.Run("fingerprint_format_no_match", func(t *testing.T) {
		// Test fingerprint that doesn't match
		differentFingerprint := "SHA256:differentfingerprintvalue"
		result := sshConnector.isKeyMatch(differentFingerprint, expectedFingerprint)
		assert.False(t, result, "Different fingerprints should not match")
	})

	t.Run("public_key_format_match", func(t *testing.T) {
		// Test full public key format that should generate matching fingerprint
		result := sshConnector.isKeyMatch(publicKeyContent, expectedFingerprint)
		assert.True(t, result, "Public key should match its fingerprint")
	})

	t.Run("public_key_format_no_match", func(t *testing.T) {
		// Use a different key's public key content
		differentKey := testKeys[1]
		differentPublicKeyContent := string(differentKey.PublicKeyBytes)

		result := sshConnector.isKeyMatch(differentPublicKeyContent, expectedFingerprint)
		assert.False(t, result, "Different public key should not match fingerprint")
	})

	t.Run("invalid_public_key_format", func(t *testing.T) {
		// Test invalid public key format falls back to string comparison
		invalidPublicKey := "invalid-ssh-key-format"
		result := sshConnector.isKeyMatch(invalidPublicKey, expectedFingerprint)
		assert.False(t, result, "Invalid public key should not match")

		// But it should match itself (fallback comparison)
		result = sshConnector.isKeyMatch(invalidPublicKey, invalidPublicKey)
		assert.True(t, result, "Invalid format should match itself via fallback")
	})

	t.Run("mixed_format_scenarios", func(t *testing.T) {
		// Test various mixed scenarios
		scenarios := []struct {
			name          string
			authorizedKey string
			presentedKey  string
			expectedMatch bool
		}{
			{
				name:          "fingerprint_matches_fingerprint",
				authorizedKey: expectedFingerprint,
				presentedKey:  expectedFingerprint,
				expectedMatch: true,
			},
			{
				name:          "public_key_matches_fingerprint",
				authorizedKey: publicKeyContent,
				presentedKey:  expectedFingerprint,
				expectedMatch: true,
			},
			{
				name:          "fingerprint_matches_same_fingerprint",
				authorizedKey: expectedFingerprint,
				presentedKey:  expectedFingerprint,
				expectedMatch: true,
			},
			{
				name:          "different_fingerprints",
				authorizedKey: "SHA256:different1",
				presentedKey:  "SHA256:different2",
				expectedMatch: false,
			},
		}

		for _, scenario := range scenarios {
			t.Run(scenario.name, func(t *testing.T) {
				result := sshConnector.isKeyMatch(scenario.authorizedKey, scenario.presentedKey)
				assert.Equal(t, scenario.expectedMatch, result,
					"Scenario %s failed: authorized=%s, presented=%s",
					scenario.name, scenario.authorizedKey, scenario.presentedKey)
			})
		}
	})
}

func TestSSHConnector_findUserByUsernameAndKey_BothFormats(t *testing.T) {
	// Generate test SSH keys
	testKeys, err := testdata.GenerateSSHKeysForTest()
	require.NoError(t, err)
	require.Len(t, testKeys, 3)

	key1Fingerprint := testKeys[0].Fingerprint
	key1PublicKey := string(testKeys[0].PublicKeyBytes)
	key2Fingerprint := testKeys[1].Fingerprint
	key2PublicKey := string(testKeys[1].PublicKeyBytes)

	// Create config with mixed key formats
	config := &Config{
		Users: map[string]UserConfig{
			"user-with-fingerprints": {
				Keys: []string{
					key1Fingerprint, // SHA256:... format
					key2Fingerprint, // SHA256:... format
				},
				UserInfo: UserInfo{
					Username: "user-with-fingerprints",
					Email:    "fingerprints@example.com",
					Groups:   []string{"fingerprint-users"},
				},
			},
			"user-with-public-keys": {
				Keys: []string{
					key1PublicKey, // ssh-ed25519 AAAAC3... format
					key2PublicKey, // ssh-ed25519 AAAAC3... format
				},
				UserInfo: UserInfo{
					Username: "user-with-public-keys",
					Email:    "publickeys@example.com",
					Groups:   []string{"public-key-users"},
				},
			},
			"user-with-mixed-keys": {
				Keys: []string{
					key1Fingerprint, // SHA256:... format
					key2PublicKey,   // ssh-ed25519 AAAAC3... format
				},
				UserInfo: UserInfo{
					Username: "user-with-mixed-keys",
					Email:    "mixed@example.com",
					Groups:   []string{"mixed-users"},
				},
			},
		},
	}

	conn, err := config.Open("test", nil)
	require.NoError(t, err)
	sshConnector := conn.(*SSHConnector)

	t.Run("fingerprint_user_matches_fingerprint", func(t *testing.T) {
		userInfo, findErr := sshConnector.findUserByUsernameAndKey("user-with-fingerprints", key1Fingerprint)
		require.NoError(t, findErr)
		assert.Equal(t, "user-with-fingerprints", userInfo.Username)
		assert.Equal(t, "fingerprints@example.com", userInfo.Email)
		assert.Contains(t, userInfo.Groups, "fingerprint-users")
	})

	t.Run("public_key_user_matches_fingerprint", func(t *testing.T) {
		userInfo, findErr := sshConnector.findUserByUsernameAndKey("user-with-public-keys", key1Fingerprint)
		require.NoError(t, findErr)
		assert.Equal(t, "user-with-public-keys", userInfo.Username)
		assert.Equal(t, "publickeys@example.com", userInfo.Email)
		assert.Contains(t, userInfo.Groups, "public-key-users")
	})

	t.Run("mixed_user_matches_fingerprint_key", func(t *testing.T) {
		// Should match the fingerprint in the mixed config
		userInfo, findErr := sshConnector.findUserByUsernameAndKey("user-with-mixed-keys", key1Fingerprint)
		require.NoError(t, findErr)
		assert.Equal(t, "user-with-mixed-keys", userInfo.Username)
		assert.Equal(t, "mixed@example.com", userInfo.Email)
		assert.Contains(t, userInfo.Groups, "mixed-users")
	})

	t.Run("mixed_user_matches_public_key", func(t *testing.T) {
		// Should match the public key in the mixed config
		userInfo, findErr := sshConnector.findUserByUsernameAndKey("user-with-mixed-keys", key2Fingerprint)
		require.NoError(t, findErr)
		assert.Equal(t, "user-with-mixed-keys", userInfo.Username)
		assert.Equal(t, "mixed@example.com", userInfo.Email)
		assert.Contains(t, userInfo.Groups, "mixed-users")
	})

	t.Run("no_match_wrong_user", func(t *testing.T) {
		_, findErr := sshConnector.findUserByUsernameAndKey("nonexistent-user", key1Fingerprint)
		require.Error(t, findErr)
		assert.Contains(t, findErr.Error(), "user nonexistent-user not found")
	})

	t.Run("no_match_wrong_key", func(t *testing.T) {
		unknownFingerprint := "SHA256:unknown-key-fingerprint"
		_, findErr := sshConnector.findUserByUsernameAndKey("user-with-fingerprints", unknownFingerprint)
		require.Error(t, findErr)
		assert.Contains(t, findErr.Error(), "key "+unknownFingerprint+" not authorized for user user-with-fingerprints")
	})
}
