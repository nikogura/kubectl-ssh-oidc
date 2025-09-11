# kubectl-ssh-oidc

A kubectl plugin that provides passwordless authentication to Kubernetes clusters using SSH keys via ssh-agent and Dex Identity Provider.

## Overview

This plugin combines:
- **SSH Key Authentication**: Uses SSH keys already loaded in your ssh-agent
- **JWT Signing**: Creates JWTs signed with your SSH private key
- **Dex Integration**: Exchanges SSH-signed JWTs for OIDC tokens
- **Kubernetes Access**: Seamlessly authenticates with kubectl

## Architecture

```
kubectl → kubectl-ssh-oidc → ssh-agent → Dex IDP → Kubernetes API Server
```

## Prerequisites

1. **SSH Agent**: Running ssh-agent with loaded SSH keys
2. **Dex**: Configured with the custom SSH connector
3. **Kubernetes**: Cluster configured to accept OIDC tokens from Dex

## Installation

### Build from Source

```bash
# Clone the repository
git clone https://github.com/your-org/kubectl-ssh-oidc
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
curl -L -o kubectl-ssh_oidc https://github.com/your-org/kubectl-ssh-oidc/releases/latest/download/kubectl-ssh_oidc-linux-amd64

# macOS AMD64 (Intel)
curl -L -o kubectl-ssh_oidc https://github.com/your-org/kubectl-ssh-oidc/releases/latest/download/kubectl-ssh_oidc-darwin-amd64

# macOS ARM64 (Apple Silicon)
curl -L -o kubectl-ssh_oidc https://github.com/your-org/kubectl-ssh-oidc/releases/latest/download/kubectl-ssh_oidc-darwin-arm64

# Make executable and move to PATH
chmod +x kubectl-ssh_oidc
sudo mv kubectl-ssh_oidc /usr/local/bin/
```

## Configuration

### 1. SSH Agent Setup

Ensure ssh-agent is running with your SSH keys:

```bash
# Start ssh-agent (if not already running)
eval $(ssh-agent -s)

# Add your SSH key
ssh-add ~/.ssh/id_rsa

# Verify keys are loaded
ssh-add -l
```

### 2. Get SSH Key Fingerprints

Generate fingerprints for Dex configuration:

```bash
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
      apiVersion: client.authentication.k8s.io/v1beta1
      command: kubectl-ssh_oidc
      args:
      - "https://dex.example.com"  # Dex URL
      - "kubectl-ssh-oidc"         # Client ID

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
      apiVersion: client.authentication.k8s.io/v1beta1
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

contexts:
- name: ssh-oidc-context
  context:
    cluster: your-cluster
    user: ssh-oidc-user
```

## Usage

### Basic Usage

```bash
# Use the configured context
kubectl config use-context ssh-oidc-context

# Now kubectl commands will authenticate via SSH
kubectl get pods
kubectl get nodes
```

### Environment Variables

Configure the plugin using environment variables:

```bash
export DEX_URL="https://dex.example.com"
export CLIENT_ID="kubectl-ssh-oidc"
export AUDIENCE="kubernetes"
export CACHE_TOKENS="true"
```

### Command Line Arguments

```bash
# Specify Dex URL and client ID
kubectl-ssh_oidc https://dex.example.com kubectl-ssh-oidc
```

## Dex Connector Installation

### 1. Build Custom Dex

The SSH connector needs to be compiled into Dex:

```bash
# Clone Dex
git clone https://github.com/dexidp/dex
cd dex

# Copy the SSH connector from this repository
cp -r /path/to/kubectl-ssh-oidc/pkg/ssh ./connector/ssh

# Update connector imports in cmd/dex/serve.go
# Add: _ "github.com/dexidp/dex/connector/ssh"

# Build Dex
make build
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
| No SSH keys in agent | `ssh-add -l` shows no keys | `ssh-add ~/.ssh/id_rsa` |
| SSH agent not running | `SSH_AUTH_SOCK` not set | `eval $(ssh-agent -s)` |
| Key not authorized in Dex | Plugin returns auth error | Check fingerprint matches Dex config |
| Token expired | Authentication fails | Plugin should auto-refresh, check Dex logs |
| OIDC not configured | kubectl auth fails | Verify kube-apiserver OIDC settings |
| Permission denied | kubectl commands fail | Check RBAC configuration |

### Debug Commands

```bash
# Check SSH agent status
make check-ssh

# Generate fingerprints for Dex config
make ssh-fingerprints

# Test plugin directly
kubectl-ssh_oidc https://dex.example.com kubectl-ssh-oidc
```

## Security Considerations

- SSH keys should be properly secured and rotated regularly
- Use strong SSH key types (RSA 4096, Ed25519, ECDSA P-384)
- Limit SSH key access through authorized_keys configuration
- Implement proper RBAC policies
- Monitor authentication logs
- Use TLS for all communications

## Development

### Prerequisites

- Go 1.24+
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