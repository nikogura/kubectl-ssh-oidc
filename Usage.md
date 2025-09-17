# kubectl-ssh-oidc

A kubectl plugin that provides passwordless authentication to Kubernetes clusters using SSH keys from ssh-agent or filesystem and Dex Identity Provider.

## Overview

This plugin combines:
- **Flexible SSH Key Authentication**: Uses SSH keys from ssh-agent or filesystem
- **Standard SSH Behavior**: Follows SSH client key discovery and iteration patterns
- **JWT Signing**: Creates standards-compliant JWTs signed with your SSH private key
- **Passphrase Support**: Interactive prompts for encrypted private keys
- **Dex Integration**: Exchanges SSH-signed JWTs for OIDC tokens
- **Kubernetes Access**: Seamlessly authenticates with kubectl

## Architecture

```
kubectl → kubectl-ssh-oidc → [ssh-agent | ~/.ssh/id_*] → Dex IDP → Kubernetes API Server
```

## Prerequisites

1. **SSH Keys**: SSH agent with loaded keys OR filesystem keys in standard locations (flexible)
2. **Dex**: Configured with the custom SSH connector
3. **Kubernetes**: Cluster configured to accept OIDC tokens from Dex

## Installation

### Build from Source

```bash
# Clone the repository
git clone https://github.com/nikogura/kubectl-ssh-oidc
cd kubectl-ssh-oidc

# Build and install
make install

# Or install system-wide
make install-system
```

### Download Binary

Download the latest release for your platform:

```bash
# Linux AMD64
curl -L -o kubectl-ssh_oidc https://github.com/nikogura/kubectl-ssh-oidc/releases/latest/download/kubectl-ssh_oidc-linux-amd64

# macOS AMD64 (Intel)
curl -L -o kubectl-ssh_oidc https://github.com/nikogura/kubectl-ssh-oidc/releases/latest/download/kubectl-ssh_oidc-darwin-amd64

# macOS ARM64 (Apple Silicon)
curl -L -o kubectl-ssh_oidc https://github.com/nikogura/kubectl-ssh-oidc/releases/latest/download/kubectl-ssh_oidc-darwin-arm64

# Make executable and move to PATH
chmod +x kubectl-ssh_oidc
sudo mv kubectl-ssh_oidc /usr/local/bin/
```

## Configuration

### 1. SSH Key Setup (Multiple Options)

The plugin supports flexible SSH key sources and follows standard SSH client behavior:

#### Option A: SSH Agent (Recommended)
```bash
# Start ssh-agent (if not already running)
eval $(ssh-agent -s)

# Add your SSH key
ssh-add ~/.ssh/id_ed25519

# Verify keys are loaded
ssh-add -l
```

#### Option B: Filesystem Keys (No Agent Required)
```bash
# Plugin automatically discovers keys from standard SSH locations:
# ~/.ssh/id_ed25519, ~/.ssh/id_rsa, ~/.ssh/id_ecdsa, etc.

# For encrypted keys, you'll be prompted for passphrase (3 attempts):
# Enter passphrase for /home/user/.ssh/id_ed25519: [hidden]
# Enter passphrase for /home/user/.ssh/id_ed25519: [hidden] (Bad passphrase, try again)

# Disable agent to use only filesystem keys:
export SSH_USE_AGENT=false
kubectl-ssh_oidc https://dex.example.com kubectl-ssh-oidc
```

#### Option C: Mixed (Agent + Filesystem)
```bash
# Plugin tries agent keys first, then filesystem keys
# This is the default behavior - no configuration needed
export SSH_USE_AGENT=true   # Default: true
kubectl-ssh_oidc https://dex.example.com kubectl-ssh-oidc
```

#### Option D: Custom Key Locations
```bash
# Specify custom SSH key paths (colon-separated)
export SSH_KEY_PATHS="/path/to/work_key:/path/to/personal_key"
export SSH_USE_AGENT=false

# Use only specified keys (ignore standard locations and agent)
export SSH_IDENTITIES_ONLY=true
kubectl-ssh_oidc https://dex.example.com kubectl-ssh-oidc
```

### 2. Get SSH Key Fingerprints

Generate fingerprints for Dex configuration:

```bash
# For agent keys
ssh-add -l

# For filesystem keys
ssh-keygen -lf ~/.ssh/id_ed25519.pub
ssh-keygen -lf ~/.ssh/id_rsa.pub

# For all keys in standard locations
for key in ~/.ssh/id_*.pub; do
  [ -f "$key" ] && ssh-keygen -lf "$key"
done

# Or use make target (shows all discoverable keys from both agent and filesystem)
make ssh-fingerprints
```

### 3. Configure Dex

Update your Dex configuration with the SSH connector and user keys:

#### Option A: Multiple Keys Per User (Recommended)

```yaml
connectors:
- type: ssh
  id: ssh
  name: SSH Key Authentication
  config:
    users:
      "your-username":
        keys:
        - "SHA256:your-work-key-fingerprint"
        - "SHA256:your-home-key-fingerprint"
        - "SHA256:your-yubikey-fingerprint"
        username: "your-username"
        email: "your-email@example.com"
        full_name: "Your Full Name"
        groups:
        - "developers"
        - "kubernetes-users"
    
    allowed_issuers:
    - "kubectl-ssh-oidc"
    
    default_groups:
    - "authenticated"
    
    token_ttl: 3600
```

#### Option B: Legacy Format (Single Key Per User)

```yaml
connectors:
- type: ssh
  id: ssh
  name: SSH Key Authentication
  config:
    authorized_keys:
      "SHA256:your-ssh-key-fingerprint":
        username: "your-username"
        email: "your-email@example.com"
        full_name: "Your Full Name"
        groups:
        - "developers"
        - "kubernetes-users"
    
    allowed_issuers:
    - "kubectl-ssh-oidc"
    
    default_groups:
    - "authenticated"
    
    token_ttl: 3600
```

### 4. Configure kubectl

Add the plugin to your kubeconfig. The plugin supports configuration via:

1. **Command line arguments** (recommended)
2. **Environment variables**

#### Command Line Configuration

```yaml
apiVersion: v1
kind: Config
users:
- name: ssh-oidc-user
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: kubectl-ssh_oidc
      args:
      - "https://dex.example.com"  # Dex URL
      - "kubectl-ssh-oidc"         # Client ID
      - "your-username"            # Username for JWT sub claim

contexts:
- name: ssh-oidc-context
  context:
    cluster: your-cluster
    user: ssh-oidc-user
```

#### Environment Variable Configuration

```yaml
apiVersion: v1
kind: Config
users:
- name: ssh-oidc-user
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: kubectl-ssh_oidc
      env:
      - name: DEX_URL
        value: "https://dex.example.com"
      - name: CLIENT_ID
        value: "kubectl-ssh-oidc"
      - name: AUDIENCE
        value: "kubernetes"
      - name: CACHE_TOKENS
        value: "true"
      - name: KUBECTL_SSH_USER
        value: "your-username"          # Username for JWT sub claim

contexts:
- name: ssh-oidc-context
  context:
    cluster: your-cluster
    user: ssh-oidc-user
```

## Usage

### Username Configuration

The plugin requires a username for the JWT `sub` claim to identify which user to authenticate in Dex. You can specify this in three ways:

1. **Command line argument** (3rd argument):
   ```bash
   kubectl-ssh_oidc https://dex.example.com kubectl-ssh-oidc your-username
   ```

2. **Environment variable**:
   ```bash
   export KUBECTL_SSH_USER=your-username
   kubectl-ssh_oidc https://dex.example.com kubectl-ssh-oidc
   ```

3. **System username fallback**: If neither is provided, uses your system username (`$USER`)

**Important**: The username must match a user configured in your Dex SSH connector configuration.

### Basic Usage

```bash
# Use the configured context
kubectl config use-context ssh-oidc-context

# Now kubectl commands will authenticate via SSH
# Plugin will try each SSH key until one succeeds
kubectl get pods
kubectl get nodes
```

### Environment Variables

Configure the plugin using environment variables:

```bash
# Authentication settings
export DEX_URL="https://dex.example.com"
export CLIENT_ID="kubectl-ssh-oidc"
export AUDIENCE="kubernetes"
export CACHE_TOKENS="true"
export KUBECTL_SSH_USER="your-username"  # Username for authentication

# SSH behavior control
export SSH_USE_AGENT="true"              # Use SSH agent (default: true)
export SSH_IDENTITIES_ONLY="false"       # Only use specified keys (default: false)
export SSH_KEY_PATHS="/path/to/key1:/path/to/key2"  # Custom SSH key paths
```

### Command Line Arguments

```bash
# Specify Dex URL, client ID, and username
kubectl-ssh_oidc https://dex.example.com kubectl-ssh-oidc your-username

# Or use environment variable for username
export KUBECTL_SSH_USER=your-username
kubectl-ssh_oidc https://dex.example.com kubectl-ssh-oidc
```

## Dex Connector Installation

### 1. Build Custom Dex

The SSH connector needs to be compiled into Dex. The integration has been tested and validated with Dex v2.39.1:

```bash
# Clone Dex (tested with v2.39.1)
git clone --branch=v2.39.1 --depth=1 https://github.com/dexidp/dex
cd dex

# Create SSH connector directory
mkdir -p connector/ssh

# Copy the SSH connector from this repository
curl -sSL https://raw.githubusercontent.com/nikogura/kubectl-ssh-oidc/main/pkg/ssh/ssh.go -o connector/ssh/ssh.go

# Add SSH connector import to server/server.go (NOT cmd/dex/serve.go)
sed -i '/\"github.com\/dexidp\/dex\/connector\/oidc\"/a\\t\"github.com/dexidp/dex/connector/ssh\"' server/server.go

# Add SSH connector to ConnectorsConfig map in server/server.go
sed -i '/\"oidc\":[[:space:]]*func()/a\\t\"ssh\":            func() ConnectorConfig { return new(ssh.Config) },' server/server.go

# Build Dex with CGO support (required for SQLite3)
CGO_ENABLED=1 make build
```

### 2. Deploy Dex

Deploy with your SSH connector configuration:

```bash
# Using Docker
docker run -p 5556:5556 -v /path/to/config.yaml:/etc/dex/config.yaml your-dex:latest serve /etc/dex/config.yaml

# Using Kubernetes
kubectl apply -f dex-deployment.yaml
```

## Kubernetes Cluster Configuration

Configure your cluster to accept OIDC tokens from Dex:

```yaml
# kube-apiserver configuration
apiVersion: kubeadm.k8s.io/v1beta3
kind: ClusterConfiguration
apiServer:
  extraArgs:
    oidc-issuer-url: "https://dex.example.com"
    oidc-client-id: "kubernetes"
    oidc-username-claim: "email"
    oidc-groups-claim: "groups"
    oidc-ca-file: "/path/to/dex-ca.pem"
```

## RBAC Configuration

Create RBAC rules for your users/groups:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ssh-oidc-developers
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: edit
subjects:
- kind: User
  name: "your-email@example.com"
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ssh-oidc-admins
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: Group
  name: "kubernetes-admins"
  apiGroup: rbac.authorization.k8s.io
```

## Troubleshooting

### Check SSH Agent

```bash
# Verify SSH agent is running
make check-ssh

# List loaded keys
ssh-add -l
```

### Debug Plugin

```bash
# Run with debug output
export DEBUG=true
kubectl-ssh_oidc https://dex.example.com
```

### Common Issues

| Issue | Diagnosis | Solution |
|-------|-----------|----------|
| No SSH keys in agent | `ssh-add -l` shows no keys | `ssh-add ~/.ssh/id_ed25519` |
| SSH agent not running | `SSH_AUTH_SOCK` not set | `eval $(ssh-agent -s)` |
| Key not authorized in Dex | Plugin returns auth error | Check fingerprint matches Dex config |
| Token expired | Authentication fails | Plugin should auto-refresh, check Dex logs |
| OIDC not configured | kubectl auth fails | Verify kube-apiserver OIDC settings |
| Permission denied | kubectl commands fail | Check RBAC configuration |

### Viewing SSH Audit Logs

The SSH connector logs all authentication attempts with structured audit entries. Check Dex logs for:

```
SSH_AUDIT: type=auth_success username=john.doe key=SHA256:L3O7OK+... issuer=kubectl-ssh-oidc status=success details="user authenticated"
SSH_AUDIT: type=auth_attempt username=jane.doe key=SHA256:abc123... issuer=kubectl-ssh-oidc status=failed details="token has expired"
```

These logs include:
- **type**: Event type (auth_success, auth_attempt)
- **username**: User attempting authentication
- **key**: SSH key fingerprint used
- **issuer**: JWT issuer identifier
- **status**: success or failed
- **details**: Additional context or error message

### Debug Commands

```bash
# Check SSH agent status
make check-ssh

# Generate fingerprints for Dex config
make ssh-fingerprints

# Test plugin directly
kubectl-ssh_oidc https://dex.example.com kubectl-ssh-oidc your-username
```

## Security Considerations

- SSH keys should be properly secured and rotated regularly
- Use strong SSH key types (RSA 4096, Ed25519, ECDSA P-384)
- Limit SSH key access through authorized_keys configuration
- Implement proper RBAC policies
- Monitor authentication logs (SSH connector provides structured audit logs)
- Use TLS for all communications

## Development

### Prerequisites

- Go 1.21+
- SSH agent with loaded keys
- Running Dex instance with SSH connector
- Kubernetes cluster with OIDC authentication configured

### Build

```bash
# Build for current platform
make build

# Cross-compile for all supported platforms
make build-all
```

### Test

```bash
# Run all tests
make test

# Run tests with coverage report
make test-coverage
```

### Lint and Format

```bash
# Lint the code
make lint

# Format the code
make fmt

# Tidy dependencies
make tidy
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

MIT License - see LICENSE file for details.