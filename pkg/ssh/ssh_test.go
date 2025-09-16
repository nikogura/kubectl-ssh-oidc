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
		AuthorizedKeys: map[string]UserInfo{
			"SHA256:test-fingerprint": {
				Username: "testuser",
				Email:    "test@example.com",
				Groups:   []string{"developers"},
				FullName: "Test User",
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

/*
// TODO: Update tests for jwt-ssh-agent approach
func TestSSHConnector_validateSSHJWT_DISABLED(t *testing.T) {
	// Setup test SSH key and connector
	testPubKey, testSigner, testPubKeyBytes, err := testdata.GenerateTestSSHKey()
	require.NoError(t, err)

	fingerprint := ssh.FingerprintSHA256(testPubKey)

	config := &Config{
		AuthorizedKeys: map[string]UserInfo{
			fingerprint: {
				Username: "testuser",
				Email:    "test@example.com",
				Groups:   []string{"developers"},
				FullName: "Test User",
			},
		},
		AllowedIssuers: []string{"test-issuer"},
		DefaultGroups:  []string{"authenticated"},
		TokenTTL:       3600,
	}

	conn, _ := config.Open("test", nil)
	sshConnector := conn.(*SSHConnector)

	t.Run("successful validation", func(t *testing.T) {
		// Create valid JWT claims
		now := time.Now()
		// claims := &SSHJWTClaims{
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
			PublicKey:      base64.StdEncoding.EncodeToString(testPubKeyBytes),
		}

		// Create unsigned token
		token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
		tokenString, signErr := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
		require.NoError(t, signErr)

		// Sign the token with SSH key
		signature, signErr := testSigner.Sign(nil, []byte(tokenString))
		require.NoError(t, signErr)

		// Create SSH signed JWT
		// sshJWT := SSHSignedJWT{
			Token:     tokenString,
			Signature: base64.StdEncoding.EncodeToString(signature.Blob),
			Format:    signature.Format,
		}

		sshJWTBytes, marshalErr := json.Marshal(sshJWT)
		require.NoError(t, marshalErr)
		require.NoError(t, err)
		sshJWTString := base64.StdEncoding.EncodeToString(sshJWTBytes)

		// Test validation
		identity, validateErr := sshConnector.validateSSHJWT(sshJWTString)

		require.NoError(t, validateErr)
		assert.Equal(t, "testuser", identity.UserID)
		assert.Equal(t, "testuser", identity.Username)
		assert.Equal(t, "test@example.com", identity.Email)
		assert.True(t, identity.EmailVerified)
		assert.Contains(t, identity.Groups, "developers")
		assert.Contains(t, identity.Groups, "authenticated")
	})

	t.Run("expired token", func(t *testing.T) {
		// Create expired JWT
		now := time.Now()
		// claims := &SSHJWTClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    "test-issuer",
				Audience:  jwt.ClaimStrings{"test-audience"},
				Subject:   fingerprint,
				ExpiresAt: jwt.NewNumericDate(now.Add(-5 * time.Minute)), // Expired
				IssuedAt:  jwt.NewNumericDate(now.Add(-10 * time.Minute)),
				NotBefore: jwt.NewNumericDate(now.Add(-10 * time.Minute)),
			},
			KeyFingerprint: fingerprint,
			KeyComment:     "test-key@example.com",
			PublicKey:      base64.StdEncoding.EncodeToString(testPubKeyBytes),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
		tokenString, tokenErr := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
		require.NoError(t, tokenErr)

		signature, signErr := testSigner.Sign(nil, []byte(tokenString))
		require.NoError(t, signErr)

		// sshJWT := SSHSignedJWT{
			Token:     tokenString,
			Signature: base64.StdEncoding.EncodeToString(signature.Blob),
			Format:    signature.Format,
		}

		sshJWTBytes, marshalErr := json.Marshal(sshJWT)
		require.NoError(t, marshalErr)
		require.NoError(t, err)
		sshJWTString := base64.StdEncoding.EncodeToString(sshJWTBytes)

		identity, validateErr := sshConnector.validateSSHJWT(sshJWTString)

		require.Error(t, validateErr)
		assert.Contains(t, validateErr.Error(), "token is expired")
		assert.Equal(t, connector.Identity{}, identity)
	})
}

func TestSSHConnector_generateAccessToken(t *testing.T) {
	config := &Config{
		TokenTTL: 3600,
	}

	conn, _ := config.Open("test", nil)
	sshConnector := conn.(*SSHConnector)

	identity := connector.Identity{
		UserID:        "testuser",
		Username:      "testuser",
		Email:         "test@example.com",
		EmailVerified: true,
		Groups:        []string{"developers", "authenticated"},
	}

	token, err := sshConnector.generateAccessToken(identity)

	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Parse token to verify claims
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		// Return the secret key used in generateAccessToken
		return []byte("your-secret-key"), nil
	})

	require.NoError(t, err)
	require.True(t, parsedToken.Valid)

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	require.True(t, ok)

	assert.Equal(t, "dex-ssh-connector", claims["iss"])
	assert.Equal(t, "testuser", claims["sub"])
	assert.Equal(t, "kubernetes", claims["aud"])
	assert.Equal(t, "test@example.com", claims["email"])
	assert.Equal(t, "testuser", claims["name"])

	// Verify groups claim
	groupsClaim, ok := claims["groups"].([]interface{})
	require.True(t, ok)
	assert.Len(t, groupsClaim, 2)
}

func TestSSHConnector_HandleTokenRequest_InvalidGrantType(t *testing.T) {
	config := &Config{}
	conn, _ := config.Open("test", nil)
	sshConnector := conn.(*SSHConnector)

	form := url.Values{}
	form.Set("grant_type", "invalid_grant_type")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	sshConnector.HandleTokenRequest(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Unsupported grant type")
}

func TestSSHConnector_HandleTokenRequest_MissingAssertion(t *testing.T) {
	config := &Config{}
	conn, _ := config.Open("test", nil)
	sshConnector := conn.(*SSHConnector)

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	sshConnector.HandleTokenRequest(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Missing assertion parameter")
}

*/

/*
// TODO: Update tests for jwt-ssh-agent approach
func TestSSHConnector_findUserByKey_DISABLED(t *testing.T) {
	// Generate test SSH keys
	testPubKey1, _, _, err := testdata.GenerateTestSSHKey()
	require.NoError(t, err)
	fingerprint1 := ssh.FingerprintSHA256(testPubKey1)

	testPubKey2, _, _, err := testdata.GenerateTestSSHKey()
	require.NoError(t, err)
	fingerprint2 := ssh.FingerprintSHA256(testPubKey2)

	testPubKey3, _, _, err := testdata.GenerateTestSSHKey()
	require.NoError(t, err)
	fingerprint3 := ssh.FingerprintSHA256(testPubKey3)

	// Test the new Users format with multiple keys per user
	t.Run("multiple keys per user - new format", func(t *testing.T) {
		config := &Config{
			Users: map[string]UserConfig{
				"alice": {
					Keys: []string{fingerprint1, fingerprint2}, // Alice has two keys
					UserInfo: UserInfo{
						Username: "alice",
						Email:    "alice@example.com",
						Groups:   []string{"developers", "admins"},
						FullName: "Alice Smith",
					},
				},
				"bob": {
					Keys: []string{fingerprint3}, // Bob has one key
					UserInfo: UserInfo{
						Username: "bob",
						Email:    "bob@example.com",
						Groups:   []string{"developers"},
						FullName: "Bob Jones",
					},
				},
			},
			DefaultGroups: []string{"authenticated"},
		}

		conn, _ := config.Open("test", nil)
		sshConnector := conn.(*SSHConnector)

		// Test finding Alice by her first key
		userInfo1, findErr1 := sshConnector.findUserByKey(fingerprint1)
		require.NoError(t, findErr1)
		assert.Equal(t, "alice", userInfo1.Username)
		assert.Equal(t, "alice@example.com", userInfo1.Email)
		assert.Contains(t, userInfo1.Groups, "developers")
		assert.Contains(t, userInfo1.Groups, "admins")

		// Test finding Alice by her second key
		userInfo2, findErr2 := sshConnector.findUserByKey(fingerprint2)
		require.NoError(t, findErr2)
		assert.Equal(t, "alice", userInfo2.Username)
		assert.Equal(t, "alice@example.com", userInfo2.Email)

		// Test finding Bob by his key
		userInfo3, findErr3 := sshConnector.findUserByKey(fingerprint3)
		require.NoError(t, findErr3)
		assert.Equal(t, "bob", userInfo3.Username)
		assert.Equal(t, "bob@example.com", userInfo3.Email)
		assert.Contains(t, userInfo3.Groups, "developers")
		assert.NotContains(t, userInfo3.Groups, "admins")
	})

	// Test backward compatibility with legacy AuthorizedKeys format
	t.Run("backward compatibility - legacy format", func(t *testing.T) {
		config := &Config{
			AuthorizedKeys: map[string]UserInfo{
				fingerprint1: {
					Username: "legacy_user",
					Email:    "legacy@example.com",
					Groups:   []string{"legacy_group"},
					FullName: "Legacy User",
				},
			},
		}

		conn, _ := config.Open("test", nil)
		sshConnector := conn.(*SSHConnector)

		legacyUserInfo, legacyErr := sshConnector.findUserByKey(fingerprint1)
		require.NoError(t, legacyErr)
		assert.Equal(t, "legacy_user", legacyUserInfo.Username)
		assert.Equal(t, "legacy@example.com", legacyUserInfo.Email)
		assert.Contains(t, legacyUserInfo.Groups, "legacy_group")
	})

	// Test mixed configuration (new format takes precedence)
	t.Run("mixed configuration - new format precedence", func(t *testing.T) {
		config := &Config{
			Users: map[string]UserConfig{
				"new_user": {
					Keys: []string{fingerprint1},
					UserInfo: UserInfo{
						Username: "new_user",
						Email:    "new@example.com",
						Groups:   []string{"new_group"},
						FullName: "New User",
					},
				},
			},
			AuthorizedKeys: map[string]UserInfo{
				fingerprint1: {
					Username: "legacy_user",
					Email:    "legacy@example.com",
					Groups:   []string{"legacy_group"},
					FullName: "Legacy User",
				},
			},
		}

		conn, _ := config.Open("test", nil)
		sshConnector := conn.(*SSHConnector)

		// New format should take precedence
		mixedUserInfo, mixedErr := sshConnector.findUserByKey(fingerprint1)
		require.NoError(t, mixedErr)
		assert.Equal(t, "new_user", mixedUserInfo.Username)
		assert.Equal(t, "new@example.com", mixedUserInfo.Email)
		assert.Contains(t, mixedUserInfo.Groups, "new_group")
	})

	// Test username auto-fill when not specified in UserInfo
	t.Run("username auto-fill", func(t *testing.T) {
		config := &Config{
			Users: map[string]UserConfig{
				"auto_user": {
					Keys: []string{fingerprint1},
					UserInfo: UserInfo{
						// Username not specified - should be auto-filled from map key
						Email:    "auto@example.com",
						Groups:   []string{"auto_group"},
						FullName: "Auto User",
					},
				},
			},
		}

		conn, _ := config.Open("test", nil)
		sshConnector := conn.(*SSHConnector)

		autoUserInfo, autoErr := sshConnector.findUserByKey(fingerprint1)
		require.NoError(t, autoErr)
		assert.Equal(t, "auto_user", autoUserInfo.Username) // Should be auto-filled
		assert.Equal(t, "auto@example.com", autoUserInfo.Email)
	})

	// Test key not found
	t.Run("key not found", func(t *testing.T) {
		config := &Config{
			Users: map[string]UserConfig{
				"test_user": {
					Keys: []string{fingerprint1},
					UserInfo: UserInfo{
						Username: "test_user",
						Email:    "test@example.com",
					},
				},
			},
		}

		conn, _ := config.Open("test", nil)
		sshConnector := conn.(*SSHConnector)

		// Try to find with a different key
		notFoundUserInfo, notFoundErr := sshConnector.findUserByKey(fingerprint2)
		require.Error(t, notFoundErr)
		assert.Contains(t, notFoundErr.Error(), "key "+fingerprint2+" not found in authorized keys")
		assert.Equal(t, UserInfo{}, notFoundUserInfo)
	})
}

*/

/*
// TODO: Update tests for jwt-ssh-agent approach
func TestSSHConnector_validateSSHJWT_MultipleKeysPerUser_DISABLED(t *testing.T) {
	// Setup test SSH keys
	testPubKey1, testSigner1, testPubKeyBytes1, err := testdata.GenerateTestSSHKey()
	require.NoError(t, err)
	fingerprint1 := ssh.FingerprintSHA256(testPubKey1)

	testPubKey2, testSigner2, testPubKeyBytes2, err := testdata.GenerateTestSSHKey()
	require.NoError(t, err)
	fingerprint2 := ssh.FingerprintSHA256(testPubKey2)

	// Configure connector with user having multiple keys
	config := &Config{
		Users: map[string]UserConfig{
			"alice": {
				Keys: []string{fingerprint1, fingerprint2}, // Alice has two keys
				UserInfo: UserInfo{
					Username: "alice",
					Email:    "alice@example.com",
					Groups:   []string{"developers", "admins"},
					FullName: "Alice Smith",
				},
			},
		},
		AllowedIssuers: []string{"test-issuer"},
		DefaultGroups:  []string{"authenticated"},
	}

	conn, _ := config.Open("test", nil)
	sshConnector := conn.(*SSHConnector)

	// Test authentication with Alice's first key
	t.Run("authenticate with first key", func(t *testing.T) {
		sshJWTString := createValidSSHJWT(t, testSigner1, testPubKeyBytes1, fingerprint1, "test-issuer")

		result, validateErr := sshConnector.validateSSHJWT(sshJWTString)
		require.NoError(t, validateErr)

		assert.Equal(t, "alice", result.UserID)
		assert.Equal(t, "alice", result.Username)
		assert.Equal(t, "alice@example.com", result.Email)
		assert.Contains(t, result.Groups, "developers")
		assert.Contains(t, result.Groups, "admins")
		assert.Contains(t, result.Groups, "authenticated") // Default group
	})

	// Test authentication with Alice's second key
	t.Run("authenticate with second key", func(t *testing.T) {
		sshJWTString := createValidSSHJWT(t, testSigner2, testPubKeyBytes2, fingerprint2, "test-issuer")

		result, validateErr := sshConnector.validateSSHJWT(sshJWTString)
		require.NoError(t, validateErr)

		// Should get the same user identity regardless of which key was used
		assert.Equal(t, "alice", result.UserID)
		assert.Equal(t, "alice", result.Username)
		assert.Equal(t, "alice@example.com", result.Email)
		assert.Contains(t, result.Groups, "developers")
		assert.Contains(t, result.Groups, "admins")
		assert.Contains(t, result.Groups, "authenticated") // Default group
	})
}

// Helper function to create a valid SSH JWT for testing.
func createValidSSHJWT(t *testing.T, signer ssh.Signer, pubKeyBytes []byte, fingerprint, issuer string) string {
	now := time.Now()
	// claims := &SSHJWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Audience:  jwt.ClaimStrings{"test-audience"},
			Subject:   fingerprint,
			ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
		KeyFingerprint: fingerprint,
		KeyComment:     "test-key@example.com",
		PublicKey:      base64.StdEncoding.EncodeToString(pubKeyBytes),
	}

	// Create unsigned token
	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)

	// Sign the token with SSH key
	signature, err := signer.Sign(nil, []byte(tokenString))
	require.NoError(t, err)

	// Create SSH signed JWT
	// sshJWT := SSHSignedJWT{
		Token:     tokenString,
		Signature: base64.StdEncoding.EncodeToString(signature.Blob),
		Format:    signature.Format,
	}

	sshJWTBytes, err := json.Marshal(sshJWT)
	require.NoError(t, err)
	sshJWTString := base64.StdEncoding.EncodeToString(sshJWTBytes)

	return sshJWTString
}
*/

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
