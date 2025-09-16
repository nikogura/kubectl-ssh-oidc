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
