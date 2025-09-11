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
