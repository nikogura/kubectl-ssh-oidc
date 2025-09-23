# kubectl-ssh-oidc

A kubectl plugin that provides passwordless authentication to Kubernetes clusters using SSH keys and Dex Identity Provider with OAuth2 Token Exchange (RFC 8693).

## Overview

This plugin combines:
- **Flexible SSH Key Authentication**: Uses SSH keys from ssh-agent or filesystem
- **Standard SSH Behavior**: Follows SSH client key discovery and iteration patterns
- **JWT Signing**: Creates standards-compliant JWTs signed with your SSH private key
- **OAuth2 Token Exchange**: Uses RFC 8693 standard for token exchange with Dex
- **Passphrase Support**: Interactive prompts for encrypted private keys
- **OIDC Integration**: Seamlessly integrates with Kubernetes OIDC authentication

## Architecture

```
kubectl → kubectl-ssh-oidc → [ssh-agent | ~/.ssh/id_*] → Dex IDP → Kubernetes API Server
```

## Prerequisites

1. **SSH Keys**: SSH agent with loaded keys OR filesystem keys in standard locations (flexible)
2. **Dex**: Using the SSH connector fork at [github.com/nikogura/dex](https://github.com/nikogura/dex)
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

### 2. Get SSH Public Keys

Get public keys for Dex configuration:

```bash
# For agent keys (get public key content)
ssh-add -L

# For filesystem keys (get public key content)
cat ~/.ssh/id_ed25519.pub
cat ~/.ssh/id_rsa.pub

# For all keys in standard locations
for key in ~/.ssh/id_*.pub; do
  [ -f "$key" ] && echo "=== $key ===" && cat "$key"
done
```

### 3. Configure Dex

Update your Dex configuration with the SSH connector and user keys:

#### Full Public Key Configuration (Required)

```yaml
connectors:
- type: ssh
  id: ssh
  name: SSH Key Authentication
  config:
    users:
      "your-username":
        keys:
        - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIYour-actual-public-key-data-here your-username@work-laptop"
        - "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... your-username@home-desktop"
        - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIYubikey-ssh-key-data-here your-username@yubikey"
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

**Security Note**: Only full SSH public keys are supported. Fingerprints are no longer accepted for security reasons - they previously allowed key injection attacks.

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
      - name: DEX_INSTANCE_ID
        value: "https://dex.example.com"  # NEW: Dex instance ID for security
      - name: TARGET_AUDIENCE
        value: "kubectl-ssh-oidc"         # NEW: Target audience for tokens
      - name: AUDIENCE
        value: "kubernetes"               # DEPRECATED: Legacy audience support
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
export DEX_INSTANCE_ID="https://dex.example.com"  # NEW: Dex instance ID for security
export TARGET_AUDIENCE="kubectl-ssh-oidc"         # NEW: Target audience for final tokens
export AUDIENCE="kubernetes"                      # DEPRECATED: Legacy audience support
export CACHE_TOKENS="true"
export KUBECTL_SSH_USER="your-username"           # Username for authentication

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

### 1. Use Dex Fork with SSH Connector

**Important**: You must use the Dex fork that includes the SSH connector with OAuth2 Token Exchange support:

```bash
# Clone the Dex fork with SSH connector
git clone https://github.com/nikogura/dex
cd dex

# Build Dex with SSH connector
make build

# Or build Docker container
docker build -t dex-ssh:latest .
```

**Alternative**: Build Docker containers directly from the fork using the provided Dockerfile.

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
| Key not authorized in Dex | Plugin returns auth error | Check public key matches Dex config |
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
- **key**: SSH key comment/identifier used
- **issuer**: JWT issuer identifier
- **status**: success or failed
- **details**: Additional context or error message

### Debug Commands

```bash
# Check SSH agent status
make check-ssh

# Get public keys for Dex config
ssh-add -L  # or cat ~/.ssh/*.pub

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