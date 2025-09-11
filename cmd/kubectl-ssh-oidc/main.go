package main

import (
	"fmt"
	"os"

	"github.com/nikogura/kubectl-ssh-oidc/pkg/kubectl"
)

func main() {
	// Load configuration
	config := kubectl.LoadConfig()

	// Create SSH-signed JWT
	sshJWT, err := kubectl.CreateSSHSignedJWT(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create SSH-signed JWT: %v\n", err)
		os.Exit(1)
	}

	// Exchange with Dex for OIDC token
	tokenResp, err := kubectl.ExchangeWithDex(config, sshJWT)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to exchange with Dex: %v\n", err)
		os.Exit(1)
	}

	// Output kubectl exec credential
	credErr := kubectl.OutputExecCredential(tokenResp.AccessToken, tokenResp.ExpiresIn)
	if credErr != nil {
		fmt.Fprintf(os.Stderr, "Failed to output credential: %v\n", credErr)
		os.Exit(1)
	}
}
