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
	credErr := kubectl.OutputExecCredential(token, tokenResp.ExpiresIn)
	if credErr != nil {
		fmt.Fprintf(os.Stderr, "Failed to output credential: %v\n", credErr)
		os.Exit(1)
	}
}
