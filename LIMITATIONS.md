# kubectl-ssh-oidc Limitations and Known Issues

This document outlines current limitations, known issues, and potential improvements for the kubectl-ssh-oidc plugin.

## ✅ **Recently Fixed (v1.1+)**

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

## 🚨 Current Limitations

### 1. No Key Caching/Performance Optimization

**Issue:** Each authentication attempt tries keys sequentially, making multiple network requests to Dex.

**Impact:** Slightly slower authentication when authorized key is not first in agent.

**Mitigation:** Typically minimal impact (1-3 keys per user in practice).

**Future Enhancement:** Could cache successful key for subsequent authentications.

### 2. No Explicit Key Selection

**Issue:** No command-line options to specify which key to use (e.g., `--ssh-key-file`).

**Impact:** Users cannot force use of specific key without managing SSH agent.

**Workaround:** Standard SSH key iteration works for 99% of use cases.

**Future Enhancement:** Add optional key selection parameters for edge cases.

### 3. Limited Error Diagnostics

**Issue:** While error messages are comprehensive, there's no pre-flight validation.

**Current:** Plugin tries each key and reports detailed failures.

**Future Enhancement:** Optional discovery endpoint to check key authorization status.

## 🛠️ Workarounds (if needed)

### Force Specific Key Usage

```bash
# Start clean agent with only desired key
ssh-add -D
ssh-add ~/.ssh/specific_key
kubectl-ssh_oidc https://dex.example.com
```

### Debug Authentication Issues

```bash
# View detailed error messages
kubectl-ssh_oidc https://dex.example.com 2>&1 | grep -A 10 "authentication failed"

# Check loaded keys
ssh-add -l

# Verify key fingerprints match Dex configuration
ssh-keygen -lf ~/.ssh/id_rsa.pub
```

## 📈 Project Status

- ✅ **Core SSH Standard Behavior**: Implemented
- ✅ **Multiple Keys Per User**: Implemented  
- ✅ **Comprehensive Error Handling**: Implemented
- ✅ **Backward Compatibility**: Maintained
- 🟡 **Performance Optimizations**: Future enhancement
- 🟡 **Advanced Key Selection**: Future enhancement

## 🎯 Future Enhancements (Low Priority)

1. **Key Caching**: Remember successful key for session
2. **Key Selection CLI**: `--ssh-key-fingerprint` option
3. **Discovery API**: Pre-flight key authorization checking
4. **Interactive Selection**: When multiple keys available
5. **Configuration Profiles**: Per-cluster key preferences

---

**Note:** The major limitations that prevented real-world usage have been resolved. The plugin now behaves like standard SSH clients and supports realistic multi-key scenarios.