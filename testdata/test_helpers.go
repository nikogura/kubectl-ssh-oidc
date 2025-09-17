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

package testdata

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// GenerateTestSSHKey generates a test SSH key pair.
func GenerateTestSSHKey() (ssh.PublicKey, ssh.Signer, []byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, nil, nil, err
	}

	publicKey := signer.PublicKey()
	publicKeyBytes := publicKey.Marshal()

	return publicKey, signer, publicKeyBytes, nil
}

// CreateTestAgentKey creates a test agent.Key.
func CreateTestAgentKey() (*agent.Key, error) {
	_, _, publicKeyBytes, err := GenerateTestSSHKey()
	if err != nil {
		return nil, err
	}

	return &agent.Key{
		Format:  "ssh-rsa",
		Blob:    publicKeyBytes,
		Comment: "test-key@example.com",
	}, nil
}

// TestSSHSignature creates a test SSH signature.
func TestSSHSignature() *ssh.Signature {
	return &ssh.Signature{
		Format: "rsa-sha2-256",
		Blob:   []byte("test-signature-blob"),
	}
}

// TestJWTPayload returns a test JWT payload.
func TestJWTPayload() string {
	return `{
		"token": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJrdWJlY3RsLXNzaC1vaWRjIiwiYXVkIjoia3ViZXJuZXRlcyIsInN1YiI6IlNIQTI1NjpYWFgiLCJleHAiOjE2ODU1NTU1NTUsImlhdCI6MTY4NTU1MjU1NSwibmJmIjoxNjg1NTUyNTU1LCJrZXlfZmluZ2VycHJpbnQiOiJTSEEyNTY6WFhYIiwia2V5X2NvbW1lbnQiOiJ0ZXN0LWtleUBleGFtcGxlLmNvbSIsInB1YmxpY19rZXkiOiJBQUFCM056YUM...."}",
		"signature": "` + base64.StdEncoding.EncodeToString([]byte("test-signature")) + `",
		"format": "rsa-sha2-256"
	}`
}

// TestDexTokenResponse returns a test Dex token response JSON.
func TestDexTokenResponse() string {
	return `{
		"access_token": "test-access-token",
		"token_type": "Bearer",
		"expires_in": 3600,
		"refresh_token": "test-refresh-token",
		"id_token": "test-id-token"
	}`
}

// TestKey1 creates a test SSH key 1.
func TestKey1() *agent.Key {
	key, err := CreateTestAgentKey()
	if err != nil {
		panic(err)
	}
	key.Comment = "test-key-1@example.com"
	return key
}

// TestKey2 creates a test SSH key 2.
func TestKey2() *agent.Key {
	// Generate a completely separate key
	_, _, publicKeyBytes2, err := GenerateTestSSHKey()
	if err != nil {
		panic(err)
	}

	return &agent.Key{
		Format:  "ssh-rsa",
		Blob:    publicKeyBytes2,
		Comment: "test-key-2@example.com",
	}
}

// TestKey3 creates a test SSH key 3.
func TestKey3() *agent.Key {
	// Generate a completely separate key
	_, _, publicKeyBytes3, err := GenerateTestSSHKey()
	if err != nil {
		panic(err)
	}

	return &agent.Key{
		Format:  "ssh-rsa",
		Blob:    publicKeyBytes3,
		Comment: "test-key-3@example.com",
	}
}

// TestPublicKey1 creates a test public key 1.
func TestPublicKey1() (ssh.PublicKey, error) {
	publicKey, _, _, err := GenerateTestSSHKey()
	return publicKey, err
}

// TestPublicKey2 creates a test public key 2.
func TestPublicKey2() (ssh.PublicKey, error) {
	publicKey, _, _, err := GenerateTestSSHKey()
	return publicKey, err
}

// TestSSHKey represents a test SSH key with its data.
type TestSSHKey struct {
	PublicKey       ssh.PublicKey
	Signer          ssh.Signer
	PublicKeyBytes  []byte
	Fingerprint     string
}

// GenerateSSHKeysForTest generates multiple test SSH keys for testing both formats.
func GenerateSSHKeysForTest() ([]TestSSHKey, error) {
	var keys []TestSSHKey

	// Generate 3 test keys
	for i := 0; i < 3; i++ {
		publicKey, signer, _, err := GenerateTestSSHKey()
		if err != nil {
			return nil, err
		}

		fingerprint := ssh.FingerprintSHA256(publicKey)
		// Format as proper SSH public key string
		publicKeyString := string(ssh.MarshalAuthorizedKey(publicKey))

		keys = append(keys, TestSSHKey{
			PublicKey:      publicKey,
			Signer:         signer,
			PublicKeyBytes: []byte(publicKeyString),
			Fingerprint:    fingerprint,
		})
	}

	return keys, nil
}
