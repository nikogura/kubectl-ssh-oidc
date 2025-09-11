# Custom Dex with SSH Connector

This custom Dex image includes the SSH connector from the [kubectl-ssh-oidc](https://github.com/nikogura/kubectl-ssh-oidc) project.

## Features

- Based on official Dex v2.39.1 with Go 1.24
- Includes SSH connector for SSH key-based authentication  
- Compatible with kubectl-ssh-oidc plugin
- Downloads only main SSH connector source (excludes tests to avoid dependency conflicts)

## SSH Connector Configuration

Add the SSH connector to your Dex configuration:

```yaml
connectors:
- type: ssh
  id: ssh
  name: SSH Key Authentication
  config:
    users:
      "your-username":
        keys:
        - "SHA256:your-ssh-key-fingerprint"
        username: "your-username"
        email: "your-email@example.com"
        groups:
        - "developers"
        - "kubernetes-users"
    
    allowed_issuers:
    - "kubectl-ssh-oidc"
    
    default_groups:
    - "authenticated"
    
    token_ttl: 3600
```

## Building

```bash
# From this directory
docker build -t custom-dex:latest .

# With specific Dex version
docker build --build-arg DEX_VERSION=v2.39.1 -t custom-dex:v2.39.1 .
```

## Usage

This image is a drop-in replacement for the standard Dex image with additional SSH connector support.