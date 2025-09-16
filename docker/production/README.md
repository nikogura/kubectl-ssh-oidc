# Custom Dex with SSH Connector

This directory contains everything needed to build a custom Dex image that includes the SSH connector from kubectl-ssh-oidc. This allows you to deploy Dex with SSH key-based authentication support.

## 🚀 Quick Start

### Build Locally
```bash
cd docker
make build
```

### Build and Push to Registry
```bash
# Docker Hub
make CONTAINER_REGISTRY=your-username build push

# GitHub Container Registry
make CONTAINER_REGISTRY=ghcr.io/your-username build push

# AWS ECR
make CONTAINER_REGISTRY=123456789012.dkr.ecr.us-west-2.amazonaws.com build push
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
| `DEX_VERSION` | `v2.39.1` | Dex version to build against |
| `KUBECTL_SSH_OIDC_VERSION` | `0.1.0` | kubectl-ssh-oidc version for SSH connector |
| `IMAGE_NAME` | `dex-ssh-oidc` | Local image name |
| `CONTAINER_REGISTRY` | (none) | Target registry for push operations |

### Registry Examples

```bash
# Docker Hub
make CONTAINER_REGISTRY=your-dockerhub-username

# GitHub Container Registry
make CONTAINER_REGISTRY=ghcr.io/your-github-username

# AWS ECR (replace with your account ID and region)
make CONTAINER_REGISTRY=123456789012.dkr.ecr.us-west-2.amazonaws.com

# Azure Container Registry
make CONTAINER_REGISTRY=yourregistry.azurecr.io

# Google Container Registry
make CONTAINER_REGISTRY=gcr.io/your-project-id
```

## 🔧 Advanced Usage

### Custom Versions
```bash
# Build with latest Dex version
make DEX_VERSION=latest build

# Build with specific versions
make DEX_VERSION=v2.40.0 KUBECTL_SSH_OIDC_VERSION=v0.2.0 build

# Build from development branch
make KUBECTL_SSH_OIDC_VERSION=main build
```

### Development Workflow
```bash
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
  dex-ssh-oidc:v2.39.1-kubectl-0.1.0 serve /etc/dex/cfg/config.yaml
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
        image: your-registry/dex-ssh-oidc:v2.39.1-kubectl-0.1.0
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

Add the SSH connector to your Dex configuration:

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
        - "SHA256:anwBv8OdPTZNsC3Und/btMdqxE71uYUugjkztuUhLH0"
        username: "john.doe"
        email: "john.doe@example.com"
        groups:
        - "developers"
        - "kubernetes-users"

    allowed_issuers:
    - "kubectl-ssh-oidc"

    allowed_clients:
    - "kubectl-ssh-oidc"

    default_groups:
    - "authenticated"

    token_ttl: 3600
```

## 🔒 Security Considerations

- **Non-Root User**: Image runs as non-root user `dex` (UID 1001)
- **Minimal Base**: Uses Alpine Linux for reduced attack surface
- **CA Certificates**: Includes trusted CA certificates for HTTPS
- **Version Pinning**: Builds against specific, known-good versions

## 🛠️ Troubleshooting

### Build Issues
```bash
# Check build info
make info

# Clean and rebuild
make clean build

# Build with specific versions
make DEX_VERSION=v2.39.1 KUBECTL_SSH_OIDC_VERSION=0.1.0 build
```

### Registry Issues
```bash
# Verify registry access
docker login your-registry.com

# Check image tags
docker images | grep dex-ssh-oidc

# Manual tag and push
docker tag dex-ssh-oidc:latest your-registry.com/dex-ssh-oidc:latest
docker push your-registry.com/dex-ssh-oidc:latest
```

## 📞 Support

For issues related to:
- **SSH Connector**: See [kubectl-ssh-oidc issues](https://github.com/nikogura/kubectl-ssh-oidc/issues)
- **Dex Integration**: Check [Dex documentation](https://dexidp.io/docs/)
- **Docker Build**: Review build logs and Dockerfile comments

## 🤝 Contributing

This Docker setup follows the same patterns as the kubectl-ssh-oidc project. Improvements and fixes are welcome through pull requests.