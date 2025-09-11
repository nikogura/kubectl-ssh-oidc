# kubectl-ssh-oidc Limitations and Known Issues

This document outlines current limitations, known issues, and potential improvements for the kubectl-ssh-oidc plugin.

## ✅ **Recently Fixed (v1.2+)**

### ~~1. Single SSH Key Support~~ - **FIXED** ✅

**✅ SOLUTION:** The plugin now follows standard SSH behavior:

**Client-side:** Tries each SSH key in sequence until one succeeds  
**Server-side:** Supports multiple SSH keys per user in Dex configuration

```bash
# Works automatically now - no workarounds needed
$ ssh-add -l
2048 SHA256:AAAA... laptop-key (RSA)    # Tries first - not authorized
4096 SHA256:BBBB... work-key (RSA)      # Tries second - succeeds ✅
256 SHA256:CCCC... yubikey (ED25519)    # Not needed

$ kubectl-ssh_oidc https://dex.example.com
# ✅ Authentication succeeds with any authorized key
```

### ~~2. Dex Single Key Per User~~ - **FIXED** ✅

**✅ SOLUTION:** Dex connector now supports multiple keys per user:

```yaml
# New configuration format
users:
  "alice":
    keys:
    - "SHA256:work-laptop-fingerprint"
    - "SHA256:home-desktop-fingerprint"
    - "SHA256:yubikey-fingerprint"
    username: "alice"
    email: "alice@example.com"
    groups: ["developers"]
```

### ~~3. SSH Agent Only~~ - **FIXED** ✅

**✅ SOLUTION:** Plugin now supports both SSH agent and filesystem keys:

**Filesystem Keys:** Automatically discovers and loads keys from standard SSH locations
**Encrypted Keys:** Prompts for passphrases using standard SSH behavior (3 attempts)
**Key Discovery:** Follows SSH client defaults (~/.ssh/id_rsa, id_ed25519, etc.)

```bash
# Works with filesystem keys (no agent required)
$ export SSH_USE_AGENT=false
$ kubectl-ssh_oidc https://dex.example.com
Enter passphrase for /home/user/.ssh/id_rsa: [hidden]
# ✅ Authentication succeeds with filesystem key

# Custom key locations
$ export SSH_KEY_PATHS="/path/to/key1:/path/to/key2"
$ kubectl-ssh_oidc https://dex.example.com
# ✅ Uses specified keys only
```

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
export KUBECTL_SSH_USER=alice       # Username for authentication
export DEX_URL=https://dex.example.com
export CLIENT_ID=kubectl-ssh-oidc
```

### Force Specific Key Usage

```bash
# Use only filesystem keys (no agent)
export SSH_USE_AGENT=false
kubectl-ssh_oidc https://dex.example.com

# Use specific key file
export SSH_KEY_PATHS="/home/user/.ssh/work_key"
export SSH_IDENTITIES_ONLY=true
kubectl-ssh_oidc https://dex.example.com
```

### Debug Authentication Issues

```bash
# View detailed error messages with key sources
kubectl-ssh_oidc https://dex.example.com 2>&1 | grep -A 10 "authentication failed"

# Check available keys
ssh-add -l  # Agent keys
ls ~/.ssh/id_*  # Filesystem keys

# Verify key fingerprints match Dex configuration
ssh-keygen -lf ~/.ssh/id_rsa.pub
```

## 📈 Project Status

- ✅ **Core SSH Standard Behavior**: Implemented
- ✅ **Multiple Keys Per User**: Implemented  
- ✅ **Filesystem Key Support**: Implemented
- ✅ **Passphrase Prompting**: Implemented
- ✅ **Comprehensive Error Handling**: Implemented
- ✅ **Backward Compatibility**: Maintained
- 🟡 **Performance Optimizations**: Future enhancement

## 🎯 Future Enhancements (Low Priority)

1. **Key Caching**: Remember successful key for session
2. **Discovery API**: Pre-flight key authorization checking  
3. **Interactive Selection**: When multiple keys available
4. **Configuration Profiles**: Per-cluster key preferences
5. **Hardware Token Support**: PKCS#11 and FIDO2 keys

---

**Note:** All major limitations have been resolved. The plugin now provides full SSH client compatibility with both agent and filesystem keys, following standard SSH behavior for key discovery, iteration, and passphrase handling.