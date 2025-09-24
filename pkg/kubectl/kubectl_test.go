/*
 * Copyright 2025 Nik Ogura <nik.ogura@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package kubectl

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
				DexURL:         "",
				ClientID:       "",
				ClientSecret:   "",
				DexInstanceID:  "",
				TargetAudience: "",
				Audience:       "",
				CacheTokens:    true,
				Username:       getSystemUsername(), // system username
				UseAgent:       true,
				IdentitiesOnly: false,
			},
		},
		{
			name: "env vars override",
			envVars: map[string]string{
				"DEX_URL":             "https://custom-dex.example.com",
				"CLIENT_ID":           "custom-client",
				"CLIENT_SECRET":       "secret123",
				"DEX_INSTANCE_ID":     "https://custom-dex.example.com",
				"TARGET_AUDIENCE":     "custom-app",
				"AUDIENCE":            "custom-audience",
				"CACHE_TOKENS":        "false",
				"KUBECTL_SSH_USER":    "testuser",
				"SSH_USE_AGENT":       "false",
				"SSH_IDENTITIES_ONLY": "true",
			},
			args: []string{"kubectl-ssh-oidc"},
			expected: &Config{
				DexURL:         "https://custom-dex.example.com",
				ClientID:       "custom-client",
				ClientSecret:   "secret123",
				DexInstanceID:  "https://custom-dex.example.com",
				TargetAudience: "custom-app",
				Audience:       "custom-audience",
				CacheTokens:    false,
				Username:       "testuser",
				UseAgent:       false,
				IdentitiesOnly: true,
			},
		},
		{
			name:    "command line args override",
			envVars: map[string]string{},
			args:    []string{"kubectl-ssh-oidc", "https://cli-dex.example.com", "cli-client"},
			expected: &Config{
				DexURL:         "https://cli-dex.example.com",
				ClientID:       "cli-client",
				ClientSecret:   "",
				DexInstanceID:  "",
				TargetAudience: "",
				Audience:       "",
				CacheTokens:    true,
				Username:       getSystemUsername(), // system username
				UseAgent:       true,
				IdentitiesOnly: false,
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

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError bool
		errorString string
	}{
		{
			name: "valid config with dual audience",
			config: &Config{
				DexURL:        "https://dex.example.com",
				ClientID:      "test-client",
				ClientSecret:  "secret",
				DexInstanceID: "https://dex.example.com",
				Username:      "testuser",
			},
			expectError: false,
		},
		{
			name: "valid config with legacy audience",
			config: &Config{
				DexURL:       "https://dex.example.com",
				ClientID:     "test-client",
				ClientSecret: "secret",
				Audience:     "kubernetes",
				Username:     "testuser",
			},
			expectError: false,
		},
		{
			name: "missing all required fields",
			config: &Config{
				CacheTokens: true,
				UseAgent:    true,
			},
			expectError: true,
			errorString: "Missing required configuration:",
		},
		{
			name: "missing audience fields",
			config: &Config{
				DexURL:       "https://dex.example.com",
				ClientID:     "test-client",
				ClientSecret: "secret",
				Username:     "testuser",
			},
			expectError: true,
			errorString: "DEX_INSTANCE_ID or AUDIENCE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConfig(tt.config)
			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorString)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestMultiKeyAuthError(t *testing.T) {
	tests := []struct {
		name      string
		keyErrors []KeyAttemptError
		expected  string
	}{
		{
			name:      "no keys attempted",
			keyErrors: []KeyAttemptError{},
			expected:  "authentication failed: no SSH keys attempted",
		},
		{
			name: "single key failure",
			keyErrors: []KeyAttemptError{
				{Index: 0, Fingerprint: "SHA256:AAAA...", Comment: "test-key", Error: assert.AnError},
			},
			expected: "authentication failed with SSH key SHA256:AAAA...: assert.AnError general error for testing",
		},
		{
			name: "multiple key failures",
			keyErrors: []KeyAttemptError{
				{Index: 0, Fingerprint: "SHA256:AAAA...", Comment: "first-key", Error: assert.AnError},
				{Index: 1, Fingerprint: "SHA256:BBBB...", Comment: "", Error: assert.AnError},
				{Index: 2, Fingerprint: "SHA256:CCCC...", Comment: "third-key", Error: assert.AnError},
			},
			expected: "authentication failed with all 3 SSH keys:\n" +
				"  key 1 (unknown): SHA256:AAAA... first-key - assert.AnError general error for testing\n" +
				"  key 2 (unknown): SHA256:BBBB... (no comment) - assert.AnError general error for testing\n" +
				"  key 3 (unknown): SHA256:CCCC... third-key - assert.AnError general error for testing\n" +
				"\n" +
				"Possible solutions:\n" +
				"  1. Ensure one of these keys is authorized in Dex configuration\n" +
				"  2. Load an authorized key: ssh-add ~/.ssh/authorized_key\n" +
				"  3. Check Dex logs for authorization details",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewMultiKeyAuthError(tt.keyErrors)
			assert.Equal(t, tt.expected, err.Error())
		})
	}
}

func TestSSHAgentClient(t *testing.T) {
	t.Run("NewSSHAgentClient", func(t *testing.T) {
		// Test that we can create a client (may fail if no agent is running)
		client, err := NewSSHAgentClient()
		if err != nil {
			// This is expected if no SSH agent is running
			// Different error messages depending on environment
			errMsg := err.Error()
			assert.True(t,
				strings.Contains(errMsg, "SSH_AUTH_SOCK") ||
					strings.Contains(errMsg, "missing address") ||
					strings.Contains(errMsg, "dial unix"),
				"Expected SSH agent error, got: %s", errMsg)
		} else {
			assert.NotNil(t, client)
		}
	})
}

func TestGetEnvOrDefault(t *testing.T) {
	tests := []struct {
		name         string
		key          string
		defaultValue string
		envValue     string
		setEnv       bool
		expected     string
	}{
		{
			name:         "use default when env not set",
			key:          "TEST_UNSET_ENV",
			defaultValue: "default-value",
			setEnv:       false,
			expected:     "default-value",
		},
		{
			name:         "use env value when set",
			key:          "TEST_SET_ENV",
			defaultValue: "default-value",
			envValue:     "env-value",
			setEnv:       true,
			expected:     "env-value",
		},
		{
			name:         "use default when env value is empty",
			key:          "TEST_EMPTY_ENV",
			defaultValue: "default-value",
			envValue:     "",
			setEnv:       true,
			expected:     "default-value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setEnv {
				t.Setenv(tt.key, tt.envValue)
			}

			result := getEnvOrDefault(tt.key, tt.defaultValue)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGenerateJTI(t *testing.T) {
	jti1, err1 := generateJTI()
	require.NoError(t, err1)
	assert.NotEmpty(t, jti1)
	assert.Len(t, jti1, 32) // 16 bytes encoded as hex = 32 chars

	jti2, err2 := generateJTI()
	require.NoError(t, err2)
	assert.NotEmpty(t, jti2)
	assert.NotEqual(t, jti1, jti2, "JTI should be unique")
}

func TestGetSystemUsername(t *testing.T) {
	username := getSystemUsername()
	assert.NotEmpty(t, username, "System username should not be empty")
}
