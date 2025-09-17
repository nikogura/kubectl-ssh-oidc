# Custom Dex with SSH Connector

This directory contains everything needed to build a custom Dex image that includes the SSH connector from kubectl-ssh-oidc. This allows you to deploy Dex with SSH key-based authentication support.

## 🚀 Quick Start

### Build Locally
```bash
cd docker
make build
```

### Build and Push to Repository
```bash
# Docker Hub
make CONTAINER_REPO=your-username/dex build push

# GitHub Container Registry
make CONTAINER_REPO=ghcr.io/your-username/dex build push

# AWS ECR
make CONTAINER_REPO=123456789012.dkr.ecr.us-west-2.amazonaws.com/dex build push
```

## 🏗️ What Gets Built

The Dockerfile creates a custom Dex image that:

1. **Clones Dex** at the specified version (default: v2.39.1)
2. **Integrates SSH Connector** from kubectl-ssh-oidc
3. **Patches Dex Server** to include SSH endpoints and handlers
4. **Builds Custom Binary** with SSH connector support
5. **Creates Minimal Runtime Image** based on Alpine Linux

## ⚙️ Configuration

### Build Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DEX_VERSION` | **Auto-detected from GitHub** | Dex version to build against |
| `KUBECTL_SSH_OIDC_VERSION` | **Auto-detected from GitHub** | kubectl-ssh-oidc version for SSH connector |
| `CONTAINER_REPO` | (none) | Target repository for push operations |

### Image Naming
The image is tagged as `dex:dex-<dex-version>-kubectl-ssh-oidc-<kubectl-ssh-oidc-version>` (e.g., `dex:dex-v2.44.0-kubectl-ssh-oidc-0.1.8`).

### Repository Examples

```bash
# Docker Hub
make CONTAINER_REPO=your-dockerhub-username/dex

# GitHub Container Registry
make CONTAINER_REPO=ghcr.io/your-github-username/dex

# AWS ECR (replace with your account ID and region)
make CONTAINER_REPO=123456789012.dkr.ecr.us-west-2.amazonaws.com/dex

# Azure Container Registry
make CONTAINER_REPO=yourregistry.azurecr.io/dex

# Google Container Registry
make CONTAINER_REPO=gcr.io/your-project-id/dex
```

## 🔧 Advanced Usage

### Version Detection and Override
```bash
# Check what versions will be used and GitHub API status
make versions

# Get build information (shows configured versions)
make info

# Override with specific versions
make DEX_VERSION=v2.40.0 KUBECTL_SSH_OIDC_VERSION=v0.2.0 build

# Build from development branch
make KUBECTL_SSH_OIDC_VERSION=main build
```

**Note on Version Detection:**
The Makefile attempts to auto-detect the latest releases from GitHub API. However, GitHub has a rate limit of 60 requests per hour for unauthenticated requests. When rate limited, the build automatically uses recent known-good fallback versions (currently Dex v2.39.1 and kubectl-ssh-oidc v0.1.8).

### Development Workflow
```bash
# Check version detection
make versions

# Get build information
make info

# Clean up images
make clean

# See all options
make help
```

## 🎯 Using the Image

### Docker Run
```bash
# Run with config file mounted
docker run -v $(pwd)/config.yaml:/etc/dex/cfg/config.yaml \
  dex:dex-v2.39.1-kubectl-ssh-oidc-0.1.8 serve /etc/dex/cfg/config.yaml
```

### Kubernetes Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: dex
spec:
  replicas: 1
  selector:
    matchLabels:
      app: dex
  template:
    metadata:
      labels:
        app: dex
    spec:
      containers:
      - name: dex
        image: your-registry/dex:dex-v2.39.1-kubectl-ssh-oidc-0.1.8
        ports:
        - containerPort: 5556
        volumeMounts:
        - name: config
          mountPath: /etc/dex/cfg
      volumes:
      - name: config
        configMap:
          name: dex-config
```

## 📋 SSH Connector Configuration

The SSH connector supports **both SSH key formats**. Add the SSH connector to your Dex configuration:

```yaml
# dex-config.yaml
issuer: https://dex.example.com

staticClients:
- id: kubectl-ssh-oidc
  name: 'kubectl SSH OIDC Plugin'
  secret: your-generated-client-secret

connectors:
- type: ssh
  id: ssh
  name: SSH Key Authentication
  config:
    users:
      "john.doe":
        keys:
        # Format 1: SSH fingerprints (recommended)
        - "SHA256:anwBv8OdPTZNsC3Und/btMdqxE71uYUugjkztuUhLH0"
        # Format 2: Full SSH public keys (also supported)
        - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample... john@hostname"
        - "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC9Uxzcz0x... john@hostname"
        username: "john.doe"
        email: "john.doe@example.com"
        groups:
        - "developers"
        - "kubernetes-users"

      "jane.smith":
        keys:
        # You can mix both formats in the same user configuration
        - "SHA256:7B2+8jXTyF9qK5mPvN3wR8sH6uY4oL1cE5gF2nA7bX0"  # Fingerprint
        - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAnother... jane@hostname"  # Full key
        username: "jane.smith"
        email: "jane.smith@example.com"
        groups:
        - "developers"

    allowed_issuers:
    - "kubectl-ssh-oidc"

    allowed_clients:
    - "kubectl-ssh-oidc"

    default_groups:
    - "authenticated"

    token_ttl: 3600
```

### SSH Key Format Notes
- ✅ **SSH Fingerprints**: `SHA256:...` format (recommended for brevity)
- ✅ **Full Public Keys**: Complete `.pub` file content (easier to copy-paste)
- ✅ **Mixed Configuration**: Both formats can be used for the same user
- ✅ **Optional Comments**: SSH public key comment field (user@hostname) is optional

## 🔒 Security Considerations

- **Non-Root User**: Image runs as non-root user `dex` (UID 1001)
- **Minimal Base**: Uses Alpine Linux for reduced attack surface
- **CA Certificates**: Includes trusted CA certificates for HTTPS
- **Version Pinning**: Builds against specific, known-good versions

## 🛠️ Troubleshooting

### Build Issues
```bash
# Check build info and current versions
make info

# Check GitHub API status and version detection
make versions

# Clean and rebuild
make clean build

# Build with specific versions (bypass version detection)
make DEX_VERSION=v2.39.1 KUBECTL_SSH_OIDC_VERSION=v0.1.8 build
```

### Version Detection Issues
```bash
# If you see older versions being used (e.g., 0.1.0 instead of 0.1.8):
make versions  # Check if GitHub API is rate limited

# Force specific versions to bypass auto-detection:
make DEX_VERSION=v2.39.1 KUBECTL_SSH_OIDC_VERSION=v0.1.8 build

# Check API rate limit status (resets hourly):
curl -s https://api.github.com/rate_limit
```

### Registry Issues
```bash
# Verify registry access
docker login your-registry.com

# Check image tags
docker images | grep dex

# Manual tag and push
docker tag dex:dex-v2.39.1-kubectl-ssh-oidc-0.1.8 your-registry.com/dex:dex-v2.39.1-kubectl-ssh-oidc-0.1.8
docker push your-registry.com/dex:dex-v2.39.1-kubectl-ssh-oidc-0.1.8
```

## 📞 Support

For issues related to:
- **SSH Connector**: See [kubectl-ssh-oidc issues](https://github.com/nikogura/kubectl-ssh-oidc/issues)
- **Dex Integration**: Check [Dex documentation](https://dexidp.io/docs/)
- **Docker Build**: Review build logs and Dockerfile comments

## 🤝 Contributing

This Docker setup follows the same patterns as the kubectl-ssh-oidc project. Improvements and fixes are welcome through pull requests.