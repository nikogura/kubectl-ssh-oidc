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
