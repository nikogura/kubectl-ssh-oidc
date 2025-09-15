package integration

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	clientauthv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
)

const (
	dexURL          = "http://localhost:5556/dex"
	testTimeout     = 60 * time.Second
	healthCheckWait = 30 * time.Second
)

// TestIntegrationSetup sets up the integration test environment.
func TestIntegrationSetup(t *testing.T) {
	// Skip if not running integration tests
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Integration tests disabled. Set INTEGRATION_TEST=true to run.")
	}

	t.Log("Starting integration test setup...")

	// Clean up any existing containers
	cleanupContainers(t)

	// Generate test SSH keys
	testDir, cleanup := setupTestDirectory(t)
	defer cleanup()

	key1Path, key1Fingerprint := generateSSHKey(t, testDir, "test_key_1")
	key2Path, key2Fingerprint := generateSSHKey(t, testDir, "test_key_2")
	key3Path, key3Fingerprint := generateSSHKey(t, testDir, "test_key_3")

	t.Logf("Generated SSH keys:")
	t.Logf("  Key 1: %s (fingerprint: %s)", key1Path, key1Fingerprint)
	t.Logf("  Key 2: %s (fingerprint: %s)", key2Path, key2Fingerprint)
	t.Logf("  Key 3: %s (fingerprint: %s)", key3Path, key3Fingerprint)

	// Set environment variables for Dex configuration
	setDexEnvironment(key1Fingerprint, key2Fingerprint, key3Fingerprint)

	// Start Docker Compose services
	startServices(t)

	// Wait for services to be healthy
	waitForDexHealthy(t)

	// Run the comprehensive authentication tests as requested by user
	t.Run("TestSuccessfulAuthWithGoodUserKey", func(t *testing.T) {
		testSuccessfulAuthWithGoodUserKey(t, testDir, key1Path, "test-user")
	})

	t.Run("TestUnsuccessfulAuthWithNonexistentUser", func(t *testing.T) {
		testUnsuccessfulAuthWithNonexistentUser(t, testDir, key1Path, "nonexistent-user")
	})

	t.Run("TestUnsuccessfulAuthWithExistingUserBadKey", func(t *testing.T) {
		testUnsuccessfulAuthWithExistingUserBadKey(t, testDir, "test-user")
	})

	t.Run("TestSuccessfulAuthWithGoodUserMultipleKeys", func(t *testing.T) {
		testSuccessfulAuthWithGoodUserMultipleKeys(t, testDir, key1Path, key2Path, "test-user")
	})

	// Cleanup
	t.Cleanup(func() {
		stopServices(t)
		cleanupContainers(t)
	})
}

// setupTestDirectory creates a temporary directory for test files.
func setupTestDirectory(t *testing.T) (string, func()) {
	testDir := t.TempDir()

	cleanup := func() {
		// t.TempDir() automatically cleans up, but keeping this for compatibility
	}

	return testDir, cleanup
}

// generateSSHKey creates a new SSH key pair and returns the private key path and fingerprint.
func generateSSHKey(t *testing.T, testDir, keyName string) (string, string) {
	// Generate ED25519 key pair
	edPublicKey, edPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Create SSH public key
	sshPublicKey, err := ssh.NewPublicKey(edPublicKey)
	require.NoError(t, err)

	// Marshal private key in OpenSSH format
	privateKeyPEM, err := ssh.MarshalPrivateKey(crypto.PrivateKey(edPrivateKey), "")
	require.NoError(t, err)

	// Write private key
	privateKeyPath := filepath.Join(testDir, keyName)
	privateKeyBytes := pem.EncodeToMemory(privateKeyPEM)
	err = os.WriteFile(privateKeyPath, privateKeyBytes, 0600)
	require.NoError(t, err)

	// Write public key
	publicKeyPath := privateKeyPath + ".pub"
	publicKeyData := ssh.MarshalAuthorizedKey(sshPublicKey)
	err = os.WriteFile(publicKeyPath, publicKeyData, 0644)
	require.NoError(t, err)

	// Get fingerprint
	fingerprint := ssh.FingerprintSHA256(sshPublicKey)

	return privateKeyPath, fingerprint
}

// setDexEnvironment sets environment variables for Dex configuration.
func setDexEnvironment(fingerprint1, fingerprint2, fingerprint3 string) {
	os.Setenv("TEST_KEY_FINGERPRINT_1", fingerprint1)
	os.Setenv("TEST_KEY_FINGERPRINT_2", fingerprint2)
	os.Setenv("TEST_KEY_FINGERPRINT_3", fingerprint3)
}

// startServices starts the Docker Compose services.
func startServices(t *testing.T) {
	t.Log("Starting Docker Compose services...")

	cmd := exec.Command("docker-compose", "up", "-d", "--build")
	cmd.Dir = "."
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("TEST_KEY_FINGERPRINT_1=%s", os.Getenv("TEST_KEY_FINGERPRINT_1")),
		fmt.Sprintf("TEST_KEY_FINGERPRINT_2=%s", os.Getenv("TEST_KEY_FINGERPRINT_2")),
		fmt.Sprintf("TEST_KEY_FINGERPRINT_3=%s", os.Getenv("TEST_KEY_FINGERPRINT_3")),
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to start services: %v\nOutput: %s", err, output)
	}

	t.Log("Services started successfully")
}

// stopServices stops the Docker Compose services.
func stopServices(t *testing.T) {
	t.Log("Stopping Docker Compose services...")

	cmd := exec.Command("docker-compose", "down", "-v")
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("Warning: Failed to stop services: %v\nOutput: %s", err, output)
	}
}

// cleanupContainers removes any existing containers.
func cleanupContainers(_ *testing.T) {
	cmd := exec.Command("docker", "system", "prune", "-f")
	cmd.Run() // Ignore errors, this is best-effort cleanup
}

// waitForDexHealthy waits for Dex to be ready to serve requests.
func waitForDexHealthy(t *testing.T) {
	t.Log("Waiting for Dex to become healthy...")

	timeout := time.Now().Add(healthCheckWait)

	for time.Now().Before(timeout) {
		resp, err := http.Get(dexURL + "/.well-known/openid-configuration")
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			t.Log("Dex is healthy and ready!")
			return
		}
		if resp != nil {
			resp.Body.Close()
		}

		t.Logf("Dex health check failed, retrying... (error: %v)", err)
		time.Sleep(2 * time.Second)
	}

	t.Fatal("Dex failed to become healthy within timeout")
}

// testSuccessfulAuthWithGoodUserKey tests successful authentication with valid user and key.
func testSuccessfulAuthWithGoodUserKey(t *testing.T, _ string, keyPath, username string) {
	t.Log("Testing successful authentication with good user/key...")

	// Build the kubectl-ssh-oidc binary
	binaryPath := buildKubectlSSHOIDC(t)

	// Set environment variables
	env := []string{
		"SSH_USE_AGENT=false",
		fmt.Sprintf("SSH_KEY_PATHS=%s", keyPath),
		"SSH_IDENTITIES_ONLY=true",
		fmt.Sprintf("KUBECTL_SSH_USER=%s", username),
	}

	// Run authentication
	cmd := exec.Command(binaryPath, dexURL, "kubectl-ssh-oidc")
	cmd.Env = append(os.Environ(), env...)

	output, err := cmd.CombinedOutput()
	outputStr := string(output)

	t.Logf("Command output: %s", outputStr)
	if err != nil {
		t.Logf("Command error: %v", err)
	}

	// Should succeed
	require.NoError(t, err, "Authentication should succeed with valid user/key")

	// Verify we got a token response
	assert.Contains(t, outputStr, "token", "Expected to receive a token")

	// Parse the kubectl exec credential response
	var execCred clientauthv1beta1.ExecCredential
	err = json.Unmarshal([]byte(outputStr), &execCred)
	require.NoError(t, err, "Should be able to parse kubectl exec credential")

	// Verify the token is present and valid
	require.NotEmpty(t, execCred.Status.Token, "Should have a token in status")

	// Validate JWT format and algorithm
	validateJWTToken(t, execCred.Status.Token, username)

	t.Log("✅ Successful authentication with good user/key verified!")
}

// testUnsuccessfulAuthWithNonexistentUser tests authentication failure with nonexistent user.
func testUnsuccessfulAuthWithNonexistentUser(t *testing.T, _ string, keyPath, username string) {
	t.Log("Testing unsuccessful authentication with nonexistent user...")

	binaryPath := buildKubectlSSHOIDC(t)

	// Set environment variables with nonexistent user
	env := []string{
		"SSH_USE_AGENT=false",
		fmt.Sprintf("SSH_KEY_PATHS=%s", keyPath),
		"SSH_IDENTITIES_ONLY=true",
		fmt.Sprintf("KUBECTL_SSH_USER=%s", username),
	}

	// Run authentication
	cmd := exec.Command(binaryPath, dexURL, "kubectl-ssh-oidc")
	cmd.Env = append(os.Environ(), env...)

	output, err := cmd.CombinedOutput()

	// Should fail
	require.Error(t, err, "Authentication should fail with nonexistent user")

	// Verify appropriate error message
	outputStr := string(output)
	assert.Contains(t, outputStr, "authentication failed", "Should contain authentication error message")

	t.Log("✅ Unsuccessful authentication with nonexistent user verified!")
}

// testUnsuccessfulAuthWithExistingUserBadKey tests authentication failure with existing user but unauthorized key.
func testUnsuccessfulAuthWithExistingUserBadKey(t *testing.T, testDir, username string) {
	t.Log("Testing unsuccessful authentication with existing user but bad key...")

	// Generate a key that's not in Dex config
	unauthorizedKeyPath, _ := generateSSHKey(t, testDir, "unauthorized_key")

	binaryPath := buildKubectlSSHOIDC(t)

	// Set environment variables with existing user but unauthorized key
	env := []string{
		"SSH_USE_AGENT=false",
		fmt.Sprintf("SSH_KEY_PATHS=%s", unauthorizedKeyPath),
		"SSH_IDENTITIES_ONLY=true",
		fmt.Sprintf("KUBECTL_SSH_USER=%s", username),
	}

	// Run authentication
	cmd := exec.Command(binaryPath, dexURL, "kubectl-ssh-oidc")
	cmd.Env = append(os.Environ(), env...)

	output, err := cmd.CombinedOutput()

	// Should fail
	require.Error(t, err, "Authentication should fail with unauthorized key for existing user")

	// Verify appropriate error message
	outputStr := string(output)
	assert.Contains(t, outputStr, "authentication failed", "Should contain authentication error message")

	t.Log("✅ Unsuccessful authentication with existing user but bad key verified!")
}

// testSuccessfulAuthWithGoodUserMultipleKeys tests successful authentication with good user and multiple keys.
func testSuccessfulAuthWithGoodUserMultipleKeys(t *testing.T, _ string, key1Path, key2Path, username string) {
	t.Log("Testing successful authentication with good user and multiple keys...")

	binaryPath := buildKubectlSSHOIDC(t)

	// Test with first key
	env1 := []string{
		"SSH_USE_AGENT=false",
		fmt.Sprintf("SSH_KEY_PATHS=%s", key1Path),
		"SSH_IDENTITIES_ONLY=true",
		fmt.Sprintf("KUBECTL_SSH_USER=%s", username),
	}

	cmd1 := exec.Command(binaryPath, dexURL, "kubectl-ssh-oidc")
	cmd1.Env = append(os.Environ(), env1...)
	output1, err1 := cmd1.CombinedOutput()

	require.NoError(t, err1, "First key should authenticate successfully")
	assert.Contains(t, string(output1), "token", "First key should receive token")

	// Test with second key
	env2 := []string{
		"SSH_USE_AGENT=false",
		fmt.Sprintf("SSH_KEY_PATHS=%s", key2Path),
		"SSH_IDENTITIES_ONLY=true",
		fmt.Sprintf("KUBECTL_SSH_USER=%s", username),
	}

	cmd2 := exec.Command(binaryPath, dexURL, "kubectl-ssh-oidc")
	cmd2.Env = append(os.Environ(), env2...)
	output2, err2 := cmd2.CombinedOutput()

	require.NoError(t, err2, "Second key should authenticate successfully")
	assert.Contains(t, string(output2), "token", "Second key should receive token")

	t.Log("✅ Successful authentication with good user and multiple keys verified!")
}

// buildKubectlSSHOIDC builds the kubectl-ssh-oidc binary for testing.
func buildKubectlSSHOIDC(t *testing.T) string {
	binaryPath := filepath.Join(t.TempDir(), "kubectl-ssh-oidc-test")

	cmd := exec.Command("go", "build", "-o", binaryPath, "../..")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to build kubectl-ssh-oidc: %v\nOutput: %s", err, output)
	}

	return binaryPath
}

// validateJWTToken validates that the token is a proper OIDC JWT with correct algorithm and claims.
func validateJWTToken(t *testing.T, tokenString, expectedUsername string) {
	// Parse JWT header without verification to check algorithm
	parts := strings.Split(tokenString, ".")
	require.Len(t, parts, 3, "JWT should have 3 parts separated by dots")

	// Decode header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err, "Should be able to decode JWT header")

	var header map[string]interface{}
	err = json.Unmarshal(headerBytes, &header)
	require.NoError(t, err, "Should be able to parse JWT header JSON")

	// Verify algorithm is HMAC-SHA256 (not SSH)
	alg, ok := header["alg"].(string)
	require.True(t, ok, "JWT header should have string algorithm")
	assert.Equal(t, "HS256", alg, "Token should use HS256 algorithm, not SSH")

	// Verify token type
	typ, ok := header["typ"].(string)
	require.True(t, ok, "JWT header should have string type")
	assert.Equal(t, "JWT", typ, "Token should be JWT type")

	t.Logf("✅ JWT header validation passed - algorithm: %s, type: %s", alg, typ)

	// Decode payload without verification to check claims
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err, "Should be able to decode JWT payload")

	var claims map[string]interface{}
	err = json.Unmarshal(payloadBytes, &claims)
	require.NoError(t, err, "Should be able to parse JWT payload JSON")

	// Verify essential OIDC claims
	sub, ok := claims["sub"].(string)
	require.True(t, ok, "JWT should have string subject claim")
	assert.Equal(t, expectedUsername, sub, "Subject should match expected username")

	iss, ok := claims["iss"].(string)
	require.True(t, ok, "JWT should have string issuer claim")
	assert.Equal(t, "https://dex-alpha.corp.terrace.fi", iss, "Issuer should match Dex URL")

	aud, ok := claims["aud"].([]interface{})
	require.True(t, ok, "JWT should have audience claim as array")
	require.Contains(t, aud, "kubernetes", "Audience should contain kubernetes")

	exp, ok := claims["exp"].(float64)
	require.True(t, ok, "JWT should have numeric expiration claim")
	assert.Greater(t, exp, float64(time.Now().Unix()), "Token should not be expired")

	iat, ok := claims["iat"].(float64)
	require.True(t, ok, "JWT should have numeric issued at claim")
	assert.LessOrEqual(t, iat, float64(time.Now().Unix()+60), "Token should have reasonable issued at time")

	// Verify user-specific claims
	email, ok := claims["email"].(string)
	require.True(t, ok, "JWT should have string email claim")
	assert.Equal(t, expectedUsername+"@example.com", email, "Email should match expected pattern")

	groups, ok := claims["groups"].([]interface{})
	require.True(t, ok, "JWT should have groups claim as array")
	assert.Contains(t, groups, "developers", "Groups should contain developers")
	assert.Contains(t, groups, "kubernetes-users", "Groups should contain kubernetes-users")

	t.Logf("✅ JWT claims validation passed - sub: %s, iss: %s, email: %s, groups: %v", sub, iss, email, groups)
}
