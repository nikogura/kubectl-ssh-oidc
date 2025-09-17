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

package mocks

import (
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// MockExtendedAgent mocks the ssh agent.ExtendedAgent interface.
type MockExtendedAgent struct {
	mock.Mock
}

// List mocks the agent.List method.
func (m *MockExtendedAgent) List() ([]*agent.Key, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*agent.Key), args.Error(1) //nolint:errcheck // mock framework handles error checking
}

// Sign mocks the agent.Sign method.
func (m *MockExtendedAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	args := m.Called(key, data)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ssh.Signature), args.Error(1) //nolint:errcheck // mock framework handles error checking
}

// Add mocks the agent.Add method.
func (m *MockExtendedAgent) Add(key agent.AddedKey) error {
	args := m.Called(key)
	return args.Error(0)
}

// Remove mocks the agent.Remove method.
func (m *MockExtendedAgent) Remove(key ssh.PublicKey) error {
	args := m.Called(key)
	return args.Error(0)
}

// RemoveAll mocks the agent.RemoveAll method.
func (m *MockExtendedAgent) RemoveAll() error {
	args := m.Called()
	return args.Error(0)
}

// Lock mocks the agent.Lock method.
func (m *MockExtendedAgent) Lock(passphrase []byte) error {
	args := m.Called(passphrase)
	return args.Error(0)
}

// Unlock mocks the agent.Unlock method.
func (m *MockExtendedAgent) Unlock(passphrase []byte) error {
	args := m.Called(passphrase)
	return args.Error(0)
}

// Signers mocks the agent.Signers method.
func (m *MockExtendedAgent) Signers() ([]ssh.Signer, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]ssh.Signer), args.Error(1) //nolint:errcheck // mock framework handles error checking
}

// SignWithFlags mocks the agent.SignWithFlags method.
func (m *MockExtendedAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	args := m.Called(key, data, flags)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ssh.Signature), args.Error(1) //nolint:errcheck // mock framework handles error checking
}

// Extension mocks the agent.Extension method.
func (m *MockExtendedAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	args := m.Called(extensionType, contents)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1) //nolint:errcheck // mock framework handles error checking
}

// MockSSHAgentClient mocks the SSHAgentClient struct and implements SSHAgentClientInterface.
type MockSSHAgentClient struct {
	mock.Mock
}

// GetKeys mocks the GetKeys method.
func (m *MockSSHAgentClient) GetKeys() ([]*agent.Key, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*agent.Key), args.Error(1) //nolint:errcheck // mock framework handles error checking
}

// SignData mocks the SignData method.
func (m *MockSSHAgentClient) SignData(data []byte) (*ssh.Signature, ssh.PublicKey, error) {
	args := m.Called(data)
	var sig *ssh.Signature
	var pubKey ssh.PublicKey

	if args.Get(0) != nil {
		sig = args.Get(0).(*ssh.Signature) //nolint:errcheck // mock framework handles error checking
	}
	if args.Get(1) != nil {
		pubKey = args.Get(1).(ssh.PublicKey) //nolint:errcheck // mock framework handles error checking
	}

	return sig, pubKey, args.Error(2)
}

// SignWithKey mocks the SignWithKey method.
func (m *MockSSHAgentClient) SignWithKey(key *agent.Key, data []byte) (*ssh.Signature, ssh.PublicKey, error) {
	args := m.Called(key, data)
	var sig *ssh.Signature
	var pubKey ssh.PublicKey

	if args.Get(0) != nil {
		sig = args.Get(0).(*ssh.Signature) //nolint:errcheck // mock framework handles error checking
	}
	if args.Get(1) != nil {
		pubKey = args.Get(1).(ssh.PublicKey) //nolint:errcheck // mock framework handles error checking
	}

	return sig, pubKey, args.Error(2)
}
