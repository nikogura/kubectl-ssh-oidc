package mocks

import (
	"net/http"

	"github.com/stretchr/testify/mock"
)

// HTTPClient interface to allow mocking of http.Client.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// MockHTTPClient mocks the HTTPClient interface.
type MockHTTPClient struct {
	mock.Mock
}

// Do mocks the http.Client.Do method.
func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	args := m.Called(req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*http.Response), args.Error(1) //nolint:errcheck // mock framework handles error checking
}
