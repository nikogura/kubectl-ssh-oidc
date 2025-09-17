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

package ssh

// Version information for the SSH connector.
// This can be set at build time using: go build -ldflags "-X github.com/nikogura/kubectl-ssh-oidc/pkg/ssh.Version=v1.2.3".
var (
	//nolint:gochecknoglobals // version must be global for build-time injection
	Version = "dev" // Version of the SSH connector (injected at build time)
)

// GetVersion returns the current version information.
func GetVersion() string {
	return Version
}
