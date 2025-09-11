# SSH Key Iteration Pattern

This document explains the standard SSH authentication pattern of trying multiple keys and why kubectl-ssh-oidc should adopt this approach.

## 🔑 Standard SSH Authentication Behavior

### How SSH Client Works

When you run `ssh user@host`, the SSH client tries each key loaded in the ssh-agent in sequence:

```bash
$ ssh -v user@host
debug1: Offering public key: RSA SHA256:AAAA... /home/user/.ssh/id_rsa
debug1: Server rejected key: (default)
debug1: Offering public key: RSA SHA256:BBBB... /home/user/.ssh/work_key
debug1: Authentication succeeded (publickey)
```

**Key Points:**
- SSH tries **each key in sequence** until one is accepted
- Order doesn't matter - it will eventually find the right key
- Users don't need to manage key order or selection
- This is the **expected behavior** for SSH-based authentication

### SSH Agent Key Order

Keys in ssh-agent are stored in **load order**:
```bash
$ ssh-add -l
2048 SHA256:AAAA... /home/user/.ssh/id_rsa (RSA)          # First loaded
4096 SHA256:BBBB... /home/user/.ssh/work_key (RSA)        # Second loaded  
256 SHA256:CCCC... /home/user/.ssh/yubikey (ED25519)      # Third loaded
```

But SSH client **tries all keys regardless of order** until authentication succeeds.

## 🚨 Current kubectl-ssh-oidc Limitation

### Current Implementation
**File:** `pkg/kubectl/kubectl.go:120`
```go
// Use the first available key
sshKey := keys[0]  // ❌ Only tries first key
```

**File:** `pkg/kubectl/kubectl.go:88`
```go
// Use the first key for signing
key := keys[0]  // ❌ Only uses first key
```

### Problem
This breaks the standard SSH paradigm:
- Users expect all keys to be tried (like `ssh` command)
- Arbitrary key order shouldn't matter
- Authentication fails if authorized key isn't first

## ✅ Recommended Solution: Key Iteration

### Implementation Pattern

```go
func CreateSSHSignedJWT(config *Config) (signedJWT string, err error) {
    sshClient, err := NewSSHAgentClient()
    if err != nil {
        return "", err
    }

    keys, err := sshClient.GetKeys()
    if err != nil {
        return "", err
    }

    if len(keys) == 0 {
        return "", errors.New("no SSH keys available in agent")
    }

    // Try each key in sequence (standard SSH behavior)
    var authErrors []string
    for i, sshKey := range keys {
        fingerprint := generateFingerprint(sshKey)
        
        signedJWT, err := tryKeyAuthentication(sshKey, config)
        if err == nil {
            // Success! Return the signed JWT
            return signedJWT, nil
        }
        
        // Log the failure and try next key
        authErrors = append(authErrors, fmt.Sprintf("key %d (%s): %v", 
            i+1, fingerprint, err))
    }
    
    // All keys failed
    return "", fmt.Errorf("authentication failed with all %d keys:\n%s", 
        len(keys), strings.Join(authErrors, "\n"))
}

func tryKeyAuthentication(sshKey *agent.Key, config *Config) (string, error) {
    // Create JWT with this specific key
    pubKey, err := ssh.ParsePublicKey(sshKey.Blob)
    if err != nil {
        return "", fmt.Errorf("failed to parse public key: %w", err)
    }

    fingerprint := ssh.FingerprintSHA256(pubKey)
    
    // Create JWT claims with this key
    claims := &SSHJWTClaims{
        RegisteredClaims: jwt.RegisteredClaims{
            Issuer:    "kubectl-ssh-oidc",
            Audience:  jwt.ClaimStrings{config.Audience},
            Subject:   fingerprint,
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
            NotBefore: jwt.NewNumericDate(time.Now()),
        },
        KeyFingerprint: fingerprint,
        KeyComment:     sshKey.Comment,
        PublicKey:      base64.StdEncoding.EncodeToString(sshKey.Blob),
    }

    // Create and sign JWT
    token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
    tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
    if err != nil {
        return "", fmt.Errorf("failed to create token: %w", err)
    }

    // Sign with SSH key
    tokenBytes := []byte(tokenString)
    signature, _, err := signWithKey(sshKey, tokenBytes)
    if err != nil {
        return "", fmt.Errorf("failed to sign with SSH key: %w", err)
    }

    // Create signed JWT structure
    signedToken := &SSHSignedJWT{
        Token:     tokenString,
        Signature: base64.StdEncoding.EncodeToString(signature.Blob),
        Format:    signature.Format,
    }

    signedTokenBytes, err := json.Marshal(signedToken)
    if err != nil {
        return "", fmt.Errorf("failed to marshal token: %w", err)
    }

    return base64.StdEncoding.EncodeToString(signedTokenBytes), nil
}
```

### Alternative: Early Validation Approach

For even better user experience, validate against Dex before creating the full JWT:

```go
func CreateSSHSignedJWT(config *Config) (signedJWT string, err error) {
    sshClient, err := NewSSHAgentClient()
    if err != nil {
        return "", err
    }

    keys, err := sshClient.GetKeys()
    if err != nil {
        return "", err
    }

    // First pass: find an authorized key without full JWT creation
    var authorizedKey *agent.Key
    var authErrors []string
    
    for i, sshKey := range keys {
        pubKey, err := ssh.ParsePublicKey(sshKey.Blob)
        if err != nil {
            authErrors = append(authErrors, fmt.Sprintf("key %d: invalid key format", i+1))
            continue
        }
        
        fingerprint := ssh.FingerprintSHA256(pubKey)
        
        // Quick check: try a minimal exchange with Dex to see if key is authorized
        if isKeyAuthorized(config, fingerprint) {
            authorizedKey = sshKey
            break
        }
        
        authErrors = append(authErrors, fmt.Sprintf("key %d (%s): not authorized", i+1, fingerprint))
    }
    
    if authorizedKey == nil {
        return "", fmt.Errorf("no authorized SSH keys found:\n%s", strings.Join(authErrors, "\n"))
    }
    
    // Create JWT with authorized key
    return createJWTWithKey(authorizedKey, config)
}

func isKeyAuthorized(config *Config, fingerprint string) bool {
    // This could be implemented as:
    // 1. Quick Dex API call to check if fingerprint is authorized
    // 2. Local cache of authorized fingerprints
    // 3. Or just proceed with full JWT creation (current approach)
    
    // For now, we'll just return true and let the full exchange determine authorization
    return true
}
```

## 🎯 User Experience Comparison

### Current Behavior (Broken)
```bash
$ ssh-add -l
2048 SHA256:AAAA... laptop_key (RSA)      # Not authorized in Dex
4096 SHA256:BBBB... work_key (RSA)        # Authorized in Dex
256 SHA256:CCCC... yubikey (ED25519)      # Not authorized in Dex

$ kubectl-ssh_oidc https://dex.example.com
Error: SSH key not authorized: SHA256:AAAA...
# ❌ Failed because it only tried the first key
```

### Standard SSH Behavior (Expected)
```bash
$ ssh user@host
# Tries laptop_key - rejected
# Tries work_key - accepted ✅  
# Authentication successful
```

### Proposed kubectl-ssh-oidc Behavior
```bash
$ kubectl-ssh_oidc https://dex.example.com
# Tries laptop_key - not authorized in Dex
# Tries work_key - authorized in Dex ✅
# Returns OIDC token
```

## 📊 Performance Considerations

### Network Requests
- **Current**: 1 request (fails if wrong key)
- **Proposed**: Up to N requests (where N = number of keys)
- **Optimization**: Early validation or caching

### SSH Agent Operations
- **Key listing**: Same (1 operation)
- **Signing**: Multiple operations (1 per key until success)
- **Impact**: Minimal - signing is fast

### Typical Scenarios
- **1 key loaded**: Same performance (1 request)
- **2-3 keys loaded**: Acceptable (2-3 requests max)
- **Many keys loaded**: Potential optimization needed

## 🔧 Implementation Options

### Option 1: Simple Iteration (Recommended)
- Try each key in sequence
- Stop at first success
- Return detailed error if all fail

**Pros:**
- Simple implementation
- Matches SSH client behavior
- Works for most users (few keys loaded)

**Cons:**
- Multiple network requests if authorized key not first
- Could be slow with many keys

### Option 2: Parallel Key Testing
- Test all keys simultaneously
- Use first successful response

**Pros:**
- Faster when many keys loaded
- Still tries all keys

**Cons:**
- More complex implementation
- Higher resource usage
- Potential rate limiting issues

### Option 3: Smart Ordering
- Try most likely keys first (e.g., Ed25519, then RSA)
- Cache successful key for future use

**Pros:**
- Optimized for common cases
- Learning behavior

**Cons:**
- Complex heuristics
- May not match user expectations

## 🚀 Implementation Plan

### Phase 1: Basic Iteration
```go
// Simple implementation - try each key until one works
for _, key := range keys {
    if signedJWT, err := tryKeyAuthentication(key, config); err == nil {
        return signedJWT, nil
    }
}
return "", fmt.Errorf("no authorized keys found")
```

### Phase 2: Better Error Handling
```go
// Collect errors from each key attempt
var keyErrors []KeyError
for i, key := range keys {
    signedJWT, err := tryKeyAuthentication(key, config)
    if err == nil {
        return signedJWT, nil
    }
    keyErrors = append(keyErrors, KeyError{Index: i, Fingerprint: fp, Error: err})
}
return "", NewMultiKeyError(keyErrors)
```

### Phase 3: Optimization
- Add key caching
- Implement parallel testing
- Add configuration for key selection strategy

## 💻 Code Changes Required

### Files to Modify:

1. **`pkg/kubectl/kubectl.go`**
   - Modify `CreateSSHSignedJWT()` to iterate through keys
   - Update `SignData()` to work with specific key
   - Add better error handling and reporting

2. **`pkg/kubectl/kubectl_test.go`**
   - Add tests for multiple key scenarios
   - Test key iteration behavior
   - Test error handling when all keys fail

3. **Documentation**
   - Update `ARCHITECTURE.md` to reflect key iteration
   - Add troubleshooting section for key issues
   - Document expected behavior

## 🧪 Testing Strategy

### Test Cases:
1. **Single key (authorized)** - Should work (baseline)
2. **Single key (unauthorized)** - Should fail with clear error
3. **Multiple keys, first authorized** - Should succeed quickly
4. **Multiple keys, second authorized** - Should succeed after trying first
5. **Multiple keys, none authorized** - Should fail with comprehensive error
6. **No keys loaded** - Should fail immediately
7. **Invalid key format** - Should skip and try next key

### Test Implementation:
```go
func TestCreateSSHSignedJWT_MultipleKeys(t *testing.T) {
    tests := []struct {
        name              string
        keys              []*agent.Key
        authorizedKeys    []string  // Fingerprints authorized in mock Dex
        expectedSuccess   bool
        expectedKeyIndex  int       // Which key should succeed
    }{
        {
            name: "second key authorized",
            keys: []*agent.Key{
                testdata.UnauthorizedKey1(),
                testdata.AuthorizedKey(),
                testdata.UnauthorizedKey2(),
            },
            authorizedKeys:   []string{testdata.AuthorizedKeyFingerprint()},
            expectedSuccess:  true,
            expectedKeyIndex: 1,
        },
        // ... more test cases
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Setup mock SSH agent with test keys
            // Setup mock Dex with authorized keys
            // Test key iteration behavior
        })
    }
}
```

This approach aligns kubectl-ssh-oidc with standard SSH client behavior and dramatically improves the user experience for multi-key environments.