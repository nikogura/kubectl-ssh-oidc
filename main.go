package main

import (
	"fmt"
	"os"

	"github.com/nikogura/kubectl-ssh-oidc/pkg/kubectl"
)

func main() {
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
