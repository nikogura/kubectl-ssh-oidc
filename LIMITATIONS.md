# kubectl-ssh-oidc Limitations and Known Issues

This document outlines current limitations, known issues, and potential improvements for the kubectl-ssh-oidc plugin.

## 🚨 Current Limitations

### 1. No Key Caching/Performance Optimization

**Issue:** Each authentication attempt tries keys sequentially, making multiple network requests to Dex.

**Impact:** Slightly slower authentication when authorized key is not first in discovery order.

**Mitigation:** Typically minimal impact (1-3 keys per user in practice).

**Future Enhancement:** Could cache successful key for subsequent authentications.

### 2. Limited Error Diagnostics

**Issue:** While error messages are comprehensive, there's no pre-flight validation.

**Current:** Plugin tries each key and reports detailed failures with source information.

**Future Enhancement:** Optional discovery endpoint to check key authorization status.

## 🛠️ Configuration and Usage

### Environment Variables

```bash
# SSH behavior control
export SSH_USE_AGENT=true          # Use SSH agent (default: true)
export SSH_IDENTITIES_ONLY=false   # Only use specified keys (default: false)
export SSH_KEY_PATHS="/path/to/key1:/path/to/key2"  # Custom key paths

# Authentication settings
export KUBECTL_SSH_USER=alice       # Username for JWT sub claim (must match Dex config)
export DEX_URL=https://dex.example.com
export CLIENT_ID=kubectl-ssh-oidc
```

### Force Specific Key Usage

```bash
# Use only filesystem keys (no agent)
export SSH_USE_AGENT=false
kubectl-ssh_oidc https://dex.example.com

# Use specific key file
export SSH_KEY_PATHS="/home/user/.ssh/id_ed25519"
export SSH_IDENTITIES_ONLY=true
kubectl-ssh_oidc https://dex.example.com
```

### Debug Authentication Issues

```bash
# Enable verbose output
kubectl-ssh_oidc https://dex.example.com 2>&1 | grep -A 10 "authentication failed"

# Check SSH agent status
ssh-add -l

# Verify key fingerprints match Dex configuration
ssh-keygen -lf ~/.ssh/id_ed25519.pub
```

## 🔮 Future Enhancements

### Potential Improvements

1. **Key Caching:** Remember successful key for faster subsequent authentications
2. **Parallel Key Testing:** Try multiple keys concurrently (with rate limiting)
3. **Pre-flight Validation:** Optional endpoint to check key status before full authentication
4. **Hardware Security Module (HSM) Support:** Enhanced integration with PIV cards and security keys
5. **Audit Logging:** Optional detailed logging for compliance and debugging

### Community Contributions

These limitations represent opportunities for community contributions. See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## 📞 Support

If you encounter issues not covered here:

1. Check the [troubleshooting guide](README.md#troubleshooting)
2. Review [GitHub issues](https://github.com/nikogura/kubectl-ssh-oidc/issues)
3. Create a new issue with detailed reproduction steps

---

**Note:** This plugin is actively maintained. Limitations are documented transparently to help users make informed decisions and to guide future development priorities.