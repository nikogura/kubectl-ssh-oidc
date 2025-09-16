# Docker Builds for kubectl-ssh-oidc

This directory contains Docker builds for creating custom Dex images with SSH connector support. There are two different build approaches for different use cases.

## 📁 Directory Structure

```
docker/
├── production/              # Production-ready builds
│   ├── Dockerfile           # Self-contained build from GitHub releases
│   ├── Makefile             # Multi-registry build automation
│   └── README.md            # Production build documentation
├── integration-testing/     # Development and testing builds
│   ├── Dockerfile           # Local build using project source
│   └── README.md            # Integration testing documentation
└── README.md                # This file
```

## 🎯 Which Build Should I Use?

### 🏭 **Production Builds** (`production/`)
**Use when**: Deploying to production, building from CI/CD, distributing images

✅ **Advantages:**
- Fully self-contained (no local source needed)
- Builds from stable GitHub releases
- **Auto-detects latest versions** from GitHub API
- Multi-registry support (Docker Hub, ECR, GCR, etc.)
- Automated build system with Makefile
- Version-controlled and reproducible

```bash
cd docker/production
make CONTAINER_REGISTRY=your-registry.com build push
```

### 🧪 **Integration Testing** (`integration-testing/`)
**Use when**: Local development, testing changes, running integration tests

✅ **Advantages:**
- Uses your local source code changes
- Fast iteration for development
- Used by project's integration test suite
- No need to commit/push changes to test

```bash
docker build -f docker/integration-testing/Dockerfile -t dex-test:latest .
```

## 🚀 Quick Start Examples

### Production Deployment
```bash
# Build and push to Docker Hub
cd docker/production
make CONTAINER_REGISTRY=myusername build push

# Use in Kubernetes
kubectl set image deployment/dex dex=myusername/dex-ssh-oidc:v2.39.1-kubectl-0.1.0
```

### Local Development
```bash
# Test your SSH connector changes
docker build -f docker/integration-testing/Dockerfile -t dex-dev:latest .
docker run -p 5556:5556 -v $(pwd)/config.yaml:/etc/dex/cfg/config.yaml dex-dev:latest
```

### Integration Testing
```bash
# This is how the project's integration tests work
docker build -f docker/integration-testing/Dockerfile -t test-dex .
# Integration tests use this image to verify SSH connector functionality
```

## 🔧 Configuration

Both builds create Dex images with:
- **SSH Connector**: Integrated from kubectl-ssh-oidc
- **Dual Key Formats**: Support for both SSH fingerprints and full public keys
- **Multiple Keys**: Support for signing key iteration
- **Direct Endpoints**: `/auth/ssh/token` for direct token exchange
- **Security**: Non-root user, minimal Alpine base
- **Compatibility**: Tested with Dex v2.39.1+

## 📖 Detailed Documentation

- **[Production Builds](production/README.md)** - Registry setup, automation, deployment
- **[Integration Testing](integration-testing/README.md)** - Local development, testing workflow

## 🆚 Comparison Summary

| Feature | Production | Integration Testing |
|---------|------------|-------------------|
| **Source** | GitHub releases | Local project files |
| **Version Detection** | Auto-detects latest from GitHub | Uses local version |
| **Build Context** | Standalone | Requires project root |
| **Registry Support** | Multi-registry | Local only |
| **Use Case** | Deployment | Development/Testing |
| **Build Speed** | Slower (downloads) | Faster (local copy) |
| **Automation** | Full Makefile | Simple docker build |
| **Reproducibility** | High (version pinned) | Depends on local state |

## 🤝 Contributing

When contributing Docker-related changes:
- **Production builds**: Update if changing deployment/registry behavior
- **Integration testing**: Update if changing development workflow or integration tests
- **Both**: Update if changing SSH connector integration or Dex compatibility

Choose the appropriate build system for your use case and see the respective README files for detailed instructions.