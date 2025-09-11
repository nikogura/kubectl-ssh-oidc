package mocks

import (
	"net/http"

	"github.com/dexidp/dex/connector"
	"github.com/stretchr/testify/mock"
)

// MockConnector mocks the dex connector.Connector interface.
type MockConnector struct {
	mock.Mock
}

// LoginURL mocks the connector.LoginURL method.
func (m *MockConnector) LoginURL(scopes connector.Scopes, callbackURL, state string) (string, error) {
	args := m.Called(scopes, callbackURL, state)
	return args.String(0), args.Error(1)
}

// HandleCallback mocks the connector.HandleCallback method.
func (m *MockConnector) HandleCallback(scopes connector.Scopes, r *http.Request) (connector.Identity, error) {
	args := m.Called(scopes, r)
	if args.Get(0) == nil {
		return connector.Identity{}, args.Error(1)
	}
	return args.Get(0).(connector.Identity), args.Error(1) //nolint:errcheck // mock framework handles error checking
}

// MockResponseWriter mocks http.ResponseWriter for testing.
type MockResponseWriter struct {
	mock.Mock
	headers http.Header
	body    []byte
	status  int
}

// NewMockResponseWriter creates a new MockResponseWriter.
func NewMockResponseWriter() *MockResponseWriter {
	return &MockResponseWriter{
		headers: make(http.Header),
	}
}

// Header mocks the Header method.
func (m *MockResponseWriter) Header() http.Header {
	return m.headers
}

// Write mocks the Write method.
func (m *MockResponseWriter) Write(data []byte) (int, error) {
	m.body = append(m.body, data...)
	args := m.Called(data)
	return args.Int(0), args.Error(1)
}

// WriteHeader mocks the WriteHeader method.
func (m *MockResponseWriter) WriteHeader(statusCode int) {
	m.status = statusCode
	m.Called(statusCode)
}

// GetBody returns the written body.
func (m *MockResponseWriter) GetBody() []byte {
	return m.body
}

// GetStatus returns the written status code.
func (m *MockResponseWriter) GetStatus() int {
	return m.status
}
