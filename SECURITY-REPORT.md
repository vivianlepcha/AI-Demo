# 🛡️ Security Guardian Report

**Repository:** `AI-Demo`
**Scan Date:** 3/11/2026, 7:51:21 PM
**Duration:** 542ms
**Path:** `/sessions/hopeful-vibrant-bohr/mnt/AI-Demo`

════════════════════════════════════════════════════════════

## 📊 Summary

**Overall Risk: 🔴 CRITICAL** (score: 100/100)

| Severity  | Count |
|-----------|-------|
| 🔴 Critical | **11** |
| 🟠 High     | **4** |
| 🟡 Medium   | **13** |
| 🔵 Low      | 0 |
| ⚪ Info     | 0 |
| **Total**   | **28** |

- 🔑 **Secrets Found:** 10
- ⚖️ **License Risks:** 0
- 🔍 **Scanners Run:** 4
- 📁 **Files Scanned:** 60

════════════════════════════════════════════════════════════

## ⚙️ Scanner Status

| Scanner | Status | Findings | Files | Duration |
|---------|--------|----------|-------|----------|
| snyk | ✅ Done (Snyk CLI not installed — install with: npm install -g snyk && snyk auth) | 0 | 1 | 3ms |
| semgrep | ✅ Done | 18 | 25 | 36ms |
| secrets | ✅ Done | 10 | 33 | 41ms |
| dependency | ✅ Done | 0 | 1 | 456ms |
| license | ⏭️ Skipped (node_modules not found — run npm install first) | 0 | 0 | 0ms |

════════════════════════════════════════════════════════════

## 🛡️ Code Security Issues

### Code Injection (9)

#### 🔴 CRITICAL security-guardian-plugin/src/scanners/semgrepScanner.ts:85

**Rule:** `eval-usage`
**Issue:** eval() usage detected — potential code injection

```
description: 'eval() usage detected — potential code injection',
```

> 💡 **Fix:** Replace eval() with safer alternatives. Never pass user input to eval().

#### 🔴 CRITICAL security-guardian-plugin/src/scanners/semgrepScanner.ts:90

**Rule:** `eval-usage`
**Issue:** eval() usage detected — potential code injection

```
recommendation: 'Replace eval() with safer alternatives. Never pass user input to eval().',
```

> 💡 **Fix:** Replace eval() with safer alternatives. Never pass user input to eval().

#### 🔴 CRITICAL security-guardian-plugin/src/scanners/semgrepScanner.ts:99

**Rule:** `eval-usage`
**Issue:** eval() usage detected — potential code injection

```
recommendation: 'Avoid new Function(). It is equivalent to eval() and can execute arbitrary code.',
```

> 💡 **Fix:** Replace eval() with safer alternatives. Never pass user input to eval().

#### 🔴 CRITICAL src/app/page.tsx:429

**Rule:** `eval-usage`
**Issue:** eval() usage detected — potential code injection

```
// VULN: eval() with user-supplied promo code — Remote Code Execution (CWE-95)
```

> 💡 **Fix:** Replace eval() with safer alternatives. Never pass user input to eval().

#### 🔴 CRITICAL src/app/page.tsx:501

**Rule:** `eval-usage`
**Issue:** eval() usage detected — potential code injection

```
{/* Promo code — uses eval() internally */}
```

> 💡 **Fix:** Replace eval() with safer alternatives. Never pass user input to eval().

#### 🔴 CRITICAL src/lib/security-utils.ts:25

**Rule:** `eval-usage`
**Issue:** eval() usage detected — potential code injection

```
// VULN-4: eval() with user-controlled input — Remote Code Execution (CWE-95)
```

> 💡 **Fix:** Replace eval() with safer alternatives. Never pass user input to eval().

#### 🔴 CRITICAL src/lib/security-utils.ts:29

**Rule:** `eval-usage`
**Issue:** eval() usage detected — potential code injection

```
return eval(expression);
```

> 💡 **Fix:** Replace eval() with safer alternatives. Never pass user input to eval().

#### 🟠 HIGH security-guardian-plugin/src/scanners/semgrepScanner.ts:96

**Rule:** `new-function-injection`
**Issue:** new Function() detected — potential code injection

```
description: 'new Function() detected — potential code injection',
```

> 💡 **Fix:** Avoid new Function(). It is equivalent to eval() and can execute arbitrary code.

#### 🟠 HIGH security-guardian-plugin/src/scanners/semgrepScanner.ts:99

**Rule:** `new-function-injection`
**Issue:** new Function() detected — potential code injection

```
recommendation: 'Avoid new Function(). It is equivalent to eval() and can execute arbitrary code.',
```

> 💡 **Fix:** Avoid new Function(). It is equivalent to eval() and can execute arbitrary code.

────────────────────────────────────────────────────────────

### Command Injection (1)

#### 🔴 CRITICAL src/app/api/search/route.ts:12

**Rule:** `command-injection-exec`
**Issue:** Potential command injection via exec/execSync with dynamic input

```
const result = execSync(`grep -r "${query}" /var/app/search-index/`);
```

> 💡 **Fix:** Avoid passing user input to shell commands. Use spawn() with an array of arguments (no shell) or sanitise input with a strict allowlist.

────────────────────────────────────────────────────────────

### Cross-Site Scripting (XSS) (4)

#### 🟠 HIGH src/app/page.tsx:453

**Rule:** `xss-dangerouslysetinnerhtml`
**Issue:** React dangerouslySetInnerHTML used with dynamic value

```
dangerouslySetInnerHTML={{ __html: `Welcome back, ${user.firstName}` }}
```

> 💡 **Fix:** Sanitise content with DOMPurify before using dangerouslySetInnerHTML.

#### 🟠 HIGH src/app/page.tsx:456

**Rule:** `xss-dangerouslysetinnerhtml`
**Issue:** React dangerouslySetInnerHTML used with dynamic value

```
dangerouslySetInnerHTML={{ __html: user.email }}
```

> 💡 **Fix:** Sanitise content with DOMPurify before using dangerouslySetInnerHTML.

#### 🟡 MEDIUM security-guardian-plugin/src/scanners/semgrepScanner.ts:164

**Rule:** `document-write`
**Issue:** document.write() usage — XSS vector

```
description: 'document.write() usage — XSS vector',
```

> 💡 **Fix:** Avoid document.write(). Use DOM APIs to create elements safely.

#### 🟡 MEDIUM security-guardian-plugin/src/scanners/semgrepScanner.ts:167

**Rule:** `document-write`
**Issue:** document.write() usage — XSS vector

```
recommendation: 'Avoid document.write(). Use DOM APIs to create elements safely.',
```

> 💡 **Fix:** Avoid document.write(). Use DOM APIs to create elements safely.

────────────────────────────────────────────────────────────

### Insecure Randomness (3)

#### 🟡 MEDIUM security-guardian-plugin/src/scanners/semgrepScanner.ts:134

**Rule:** `math-random-security`
**Issue:** Math.random() used in security-sensitive context

```
description: 'Math.random() used in security-sensitive context',
```

> 💡 **Fix:** Use crypto.randomBytes() or crypto.randomUUID() for security tokens.

#### 🟡 MEDIUM src/app/page.tsx:599

**Rule:** `math-random-security`
**Issue:** Math.random() used in security-sensitive context

```
// VULN: Insecure session token using Math.random() (CWE-338)
```

> 💡 **Fix:** Use crypto.randomBytes() or crypto.randomUUID() for security tokens.

#### 🟡 MEDIUM src/lib/security-utils.ts:22

**Rule:** `math-random-security`
**Issue:** Math.random() used in security-sensitive context

```
return Math.random().toString(36).substring(2) + Date.now().toString(36);
```

> 💡 **Fix:** Use crypto.randomBytes() or crypto.randomUUID() for security tokens.

────────────────────────────────────────────────────────────

### Insecure Cryptography (1)

#### 🟡 MEDIUM src/lib/security-utils.ts:16

**Rule:** `weak-hash-md5`
**Issue:** MD5 hash usage detected — weak algorithm

```
return crypto.createHash('md5').update(password).digest('hex');
```

> 💡 **Fix:** Replace MD5 with SHA-256 or SHA-3. MD5 is cryptographically broken.

────────────────────────────────────────────────────────────

════════════════════════════════════════════════════════════

## 🔑 Exposed Secrets

> ⚠️ **ACTION REQUIRED:** Rotate any exposed credentials immediately!

### 🔴 CRITICAL — PRIVATE KEY

**File:** `security-guardian-plugin/src/scanners/secretScanner.ts` (line 124)
**Type:** private_key
**Match (redacted):** `-----BEGIN OPENSSH PRIVATE KEY-----`

```
regex: /----****----/,
```

> 💡 **Fix:** Remove the secret from source code. Use environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault). Rotate the exposed credential immediately.

────────────────────────────────────────────────────────────

### 🔴 CRITICAL — SSH KEY

**File:** `security-guardian-plugin/src/scanners/secretScanner.ts` (line 124)
**Type:** ssh_key
**Match (redacted):** `-----BEGIN OPENSSH PRIVATE KEY-----`

```
regex: /----****----/,
```

> 💡 **Fix:** Remove the secret from source code. Use environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault). Rotate the exposed credential immediately.

────────────────────────────────────────────────────────────

### 🔴 CRITICAL — PGP KEY

**File:** `security-guardian-plugin/src/scanners/secretScanner.ts` (line 130)
**Type:** pgp_key
**Match (redacted):** `-----BEGIN PGP PRIVATE KEY BLOCK-----`

```
regex: /----****----/,
```

> 💡 **Fix:** Remove the secret from source code. Use environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault). Rotate the exposed credential immediately.

────────────────────────────────────────────────────────────

### 🟡 MEDIUM — GENERIC PASSWORD

**File:** `src/app/api/user/route.ts` (line 12)
**Type:** generic_password
**Match (redacted):** `Pand****024!`

```
const DB_PASSWORD = 'Pand****024!';
```

> 💡 **Fix:** Remove the secret from source code. Use environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault). Rotate the exposed credential immediately.

────────────────────────────────────────────────────────────

### 🟡 MEDIUM — JWT TOKEN

**File:** `src/app/api/user/route.ts` (line 13)
**Type:** jwt_token
**Match (redacted):** `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.pandora_internal`

```
const INTERNAL_API_TOKEN = 'Bearer eyJh****rnal';
```

> 💡 **Fix:** Remove the secret from source code. Use environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault). Rotate the exposed credential immediately.

────────────────────────────────────────────────────────────

### 🟡 MEDIUM — GENERIC API KEY

**File:** `src/app/page.tsx` (line 10)
**Type:** generic_api_key
**Match (redacted):** `pk_l****lo8B`

```
const PANDORA_API_KEY    = 'pk_l****lo8B';
```

> 💡 **Fix:** Remove the secret from source code. Use environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault). Rotate the exposed credential immediately.

────────────────────────────────────────────────────────────

### 🟡 MEDIUM — GENERIC API KEY

**File:** `src/lib/security-utils.ts` (line 8)
**Type:** generic_api_key
**Match (redacted):** `sk-p****7e6f`

```
const API_KEY        = 'sk-p****7e6f';
```

> 💡 **Fix:** Remove the secret from source code. Use environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault). Rotate the exposed credential immediately.

────────────────────────────────────────────────────────────

### 🟡 MEDIUM — GENERIC SECRET

**File:** `src/lib/security-utils.ts` (line 9)
**Type:** generic_secret
**Match (redacted):** `pand****024!`

```
const JWT_SECRET     = 'pand****024!';
```

> 💡 **Fix:** Remove the secret from source code. Use environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault). Rotate the exposed credential immediately.

────────────────────────────────────────────────────────────

### 🟡 MEDIUM — GENERIC PASSWORD

**File:** `src/lib/security-utils.ts` (line 10)
**Type:** generic_password
**Match (redacted):** `Pand****n123`

```
const DB_PASSWORD    = 'Pand****n123';
```

> 💡 **Fix:** Remove the secret from source code. Use environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault). Rotate the exposed credential immediately.

────────────────────────────────────────────────────────────

### 🟡 MEDIUM — GENERIC SECRET

**File:** `src/lib/security-utils.ts` (line 11)
**Type:** generic_secret
**Match (redacted):** `sk_l****ONLY`

```
const STRIPE_SECRET  = 'sk_l****ONLY'; // DEMO: not a real key
```

> 💡 **Fix:** Remove the secret from source code. Use environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault). Rotate the exposed credential immediately.

────────────────────────────────────────────────────────────

════════════════════════════════════════════════════════════

## 🚀 Recommended Actions

1. **URGENT:** Rotate 10 exposed credential(s) immediately. Run `git filter-branch` or use BFG Repo Cleaner to purge from history.

2. Remediate 8 critical code security issues (injection, eval, etc.) before deploying.


────────────────────────────────────────────────────────────

*Generated by [Security Guardian Plugin](https://github.com/pandora-jewelry/security-guardian-plugin) — Read-only scan, no changes made.*