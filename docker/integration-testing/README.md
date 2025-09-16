# Integration Testing Docker Build

This Dockerfile is designed for **integration testing** and **local development** of the kubectl-ssh-oidc project. It builds a custom Dex image using the local source code from your development environment.

## 🎯 Purpose

- **Integration Testing**: Used by the project's integration test suite
- **Local Development**: Quick builds using your current local changes
- **Development Workflow**: Test SSH connector changes without publishing releases

## 🚀 Usage

### From Project Root
```bash
# Build using local source code
docker build -f docker/integration-testing/Dockerfile -t dex-ssh-oidc:test .

# Build with specific Dex version
docker build -f docker/integration-testing/Dockerfile --build-arg DEX_VERSION=v2.40.0 -t dex-ssh-oidc:test .
```

### Integration Test Usage
```bash
# This is how the integration tests use this Dockerfile
cd /path/to/kubectl-ssh-oidc
docker build -f docker/integration-testing/Dockerfile -t test-dex:latest .
docker run -d --name test-dex -p 5556:5556 -v $(pwd)/test-config.yaml:/etc/dex/cfg/config.yaml test-dex:latest
```

## ⚙️ Build Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `DEX_VERSION` | `v2.39.1` | Version of Dex to build against |

## 🔧 How It Works

1. **Uses Local Source**: Copies SSH connector from your local `pkg/ssh/` directory
2. **Patches Dex**: Integrates the SSH connector into a fresh Dex clone
3. **Local Build**: Perfect for testing changes before they're committed
4. **Fast Iteration**: No need to push changes to GitHub to test

## 📁 Context Requirements

This Dockerfile expects to be run from the **kubectl-ssh-oidc project root** because it needs:
```
kubectl-ssh-oidc/
├── pkg/ssh/ssh.go           # SSH connector implementation
├── pkg/ssh/version.go       # Version information
└── docker/integration-testing/Dockerfile
```

## 🆚 vs Production Build

| Aspect | Integration Testing | Production |
|--------|-------------------|------------|
| **Source** | Local `pkg/ssh/` | GitHub releases |
| **Purpose** | Testing changes | Stable deployments |
| **Context** | Project root | Standalone |
| **Speed** | Fast (uses local code) | Slower (downloads) |
| **Registry** | Local only | Multi-registry support |

## 💡 Development Tips

```bash
# Quick rebuild after SSH connector changes
docker build -f docker/integration-testing/Dockerfile -t dex-test:latest .

# Test with your changes
docker run --rm -p 5556:5556 \
  -v $(pwd)/test-config.yaml:/etc/dex/cfg/config.yaml \
  dex-test:latest serve /etc/dex/cfg/config.yaml

# Check logs
docker logs dex-test
```

## 🔗 Related

- **Production Builds**: See [`../production/README.md`](../production/README.md)
- **Integration Tests**: See project root integration test documentation
- **SSH Connector**: See [`../../pkg/ssh/`](../../pkg/ssh/)

This build approach enables rapid development and testing of SSH connector changes without the overhead of the full production build process.