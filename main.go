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
	"encoding/json"
	"fmt"
	"os"

	"github.com/nikogura/kubectl-ssh-oidc/pkg/kubectl"
	clientauthv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
)

func main() {
	// Check if we're being called as an ExecCredential plugin
	execInfo := os.Getenv("KUBERNETES_EXEC_INFO")
	if execInfo != "" {
		// Parse the ExecCredential input
		var execCredential clientauthv1.ExecCredential
		err := json.Unmarshal([]byte(execInfo), &execCredential)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse KUBERNETES_EXEC_INFO: %v\n", err)
			os.Exit(1)
		}

		// We're being called by kubectl as a credential provider
		// The config should still come from environment variables set in kubeconfig
	}

	// Load configuration
	config := kubectl.LoadConfig()

	// Validate configuration and exit with clear error if anything is missing
	err := kubectl.ValidateConfig(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	// Create SSH-signed JWT and authenticate with Dex (tests each key until one is authorized)
	sshJWT, err := kubectl.CreateSSHSignedJWT(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to authenticate with SSH key: %v\n", err)
		os.Exit(1)
	}

	// Exchange the authorized JWT for OIDC token
	tokenResp, err := kubectl.ExchangeWithDex(config, sshJWT)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to exchange with Dex: %v\n", err)
		os.Exit(1)
	}

	// Use ID token for Kubernetes authentication if available, otherwise use access token
	token := tokenResp.AccessToken
	if tokenResp.IDToken != "" {
		token = tokenResp.IDToken
	}

	// Output kubectl exec credential with server-generated OIDC token
	var execCredSpec *clientauthv1.ExecCredentialSpec
	if execInfo != "" {
		var execCredential clientauthv1.ExecCredential
		unmarshalErr := json.Unmarshal([]byte(execInfo), &execCredential)
		if unmarshalErr == nil {
			execCredSpec = &execCredential.Spec
		}
	}

	credErr := kubectl.OutputExecCredentialWithSpec(token, tokenResp.ExpiresIn, execCredSpec)
	if credErr != nil {
		fmt.Fprintf(os.Stderr, "Failed to output credential: %v\n", credErr)
		os.Exit(1)
	}
}
