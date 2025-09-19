//go:build integration

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

package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTokenExchangeFlow tests the OAuth2 Token Exchange authentication flow against a real Dex instance.
// This test requires:
// 1. A running Dex instance with SSH connector at DEX_URL
// 2. SSH agent running with authorized key loaded
// 3. Environment variables: DEX_URL, CLIENT_ID, KUBECTL_SSH_USER
func TestTokenExchangeFlow(t *testing.T) {
	// Check required environment variables
	dexURL := os.Getenv("DEX_URL")
	clientID := os.Getenv("CLIENT_ID")
	kubectlSSHUser := os.Getenv("KUBECTL_SSH_USER")

	if dexURL == "" || clientID == "" || kubectlSSHUser == "" {
		t.Skip("Required environment variables not set (DEX_URL, CLIENT_ID, KUBECTL_SSH_USER)")
	}

	if os.Getenv("SSH_AUTH_SOCK") == "" {
		t.Skip("SSH_AUTH_SOCK not set - SSH agent not running")
	}

	// Test OAuth2 Token Exchange flow
	cmd := exec.Command("./kubectl-ssh-oidc")
	cmd.Env = append(os.Environ(),
		"DEX_URL="+dexURL,
		"CLIENT_ID="+clientID,
		"KUBECTL_SSH_USER="+kubectlSSHUser,
	)

	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Token Exchange flow failed: %s", string(output))

	// Verify output is valid ExecCredential JSON
	assert.Contains(t, string(output), `"kind": "ExecCredential"`)
	assert.Contains(t, string(output), `"apiVersion": "client.authentication.k8s.io/v1"`)
	assert.Contains(t, string(output), `"token":`)
}

// TestTokenExchangeWithClientSecret tests the OAuth2 Token Exchange flow with client secret.
// This test requires:
// 1. A running Dex instance with SSH connector supporting TokenIdentityConnector at DEX_URL
// 2. SSH agent running with authorized key loaded
// 3. Environment variables: DEX_URL, CLIENT_ID, CLIENT_SECRET, KUBECTL_SSH_USER
func TestTokenExchangeWithClientSecret(t *testing.T) {
	// Check required environment variables
	dexURL := os.Getenv("DEX_URL")
	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")
	kubectlSSHUser := os.Getenv("KUBECTL_SSH_USER")

	if dexURL == "" || clientID == "" || clientSecret == "" || kubectlSSHUser == "" {
		t.Skip("Required environment variables not set (DEX_URL, CLIENT_ID, CLIENT_SECRET, KUBECTL_SSH_USER)")
	}

	if os.Getenv("SSH_AUTH_SOCK") == "" {
		t.Skip("SSH_AUTH_SOCK not set - SSH agent not running")
	}

	// Test OAuth2 Token Exchange flow with client secret
	cmd := exec.Command("./kubectl-ssh-oidc")
	cmd.Env = append(os.Environ(),
		"DEX_URL="+dexURL,
		"CLIENT_ID="+clientID,
		"CLIENT_SECRET="+clientSecret,
		"KUBECTL_SSH_USER="+kubectlSSHUser,
	)

	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Token Exchange with client secret failed: %s", string(output))

	// Verify output is valid ExecCredential JSON
	assert.Contains(t, string(output), `"kind": "ExecCredential"`)
	assert.Contains(t, string(output), `"apiVersion": "client.authentication.k8s.io/v1"`)
	assert.Contains(t, string(output), `"token":`)

	// Verify we got a proper ID token by checking for longer token length
	// (ID tokens contain more claims than access tokens)
	outputStr := string(output)
	tokenStart := strings.Index(outputStr, `"token": "`) + 10
	tokenEnd := strings.Index(outputStr[tokenStart:], `"`)
	if tokenStart > 9 && tokenEnd > 0 {
		token := outputStr[tokenStart : tokenStart+tokenEnd]
		// ID tokens should be longer due to additional claims
		assert.Greater(t, len(token), 600, "Token should be an ID token with multiple claims")
	}
}
