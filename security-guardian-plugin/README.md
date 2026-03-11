# 🛡️ Security Guardian Plugin

A Claude Code plugin that scans your repository for security vulnerabilities, exposed secrets, risky licences, and code security issues — all from a single slash command.

**No external CLI required.** All scanners run with Node.js built-ins. Snyk CLI is used as an enhancement if available.

---

## Features

| Engine | What It Detects |
|--------|----------------|
| 🔍 **Snyk** | CVEs, supply chain risks, lock file integrity |
| 🛡️ **Semgrep** | SQL injection, XSS, eval, weak crypto, SSRF, prototype pollution |
| 🔑 **Secret Scanner** | AWS keys, GitHub tokens, JWT, Stripe keys, DB URLs, etc. |
| 📦 **Dependency Audit** | npm audit vulnerabilities, outdated & deprecated packages |
| ⚖️ **License Scanner** | GPL, AGPL, SSPL, BUSL and other risky licences |

---

## Quick Start

### Option A — Install globally (recommended)

```bash
npm install -g @security-guardian/claude-plugin
```

Then in any repo, open Claude Code and run:

```
/security-guardian
```

---

### Option B — Install as a dev dependency

```bash
npm install --save-dev @security-guardian/claude-plugin
```

Then use via:

```
/security-guardian
```

---

### Option C — Copy plugin directly (no npm publish needed)

1. Copy the `security-guardian-plugin` folder to your home directory or a central location:
   ```bash
   cp -r security-guardian-plugin ~/security-guardian-plugin
   ```

2. Install the Claude Code commands globally:
   ```bash
   mkdir -p ~/.claude/commands
   cp -r ~/security-guardian-plugin/.claude/commands/*.md ~/.claude/commands/
   ```

3. Open any repository in Claude Code and run:
   ```
   /security-guardian
   ```

---

### Option D — Project-local (per-repo)

Copy the `.claude` folder into your repository:

```bash
cp -r security-guardian-plugin/.claude /path/to/your-repo/.claude
```

Then from within that repo in Claude Code:
```
/security-guardian
```

---

## Slash Commands

| Command | Description |
|---------|-------------|
| `/security-guardian` | Full repository scan (all 5 engines) |
| `/security-guardian --changed` | Scan only git-modified files |
| `/security-guardian --dependencies` | Dependency vulnerabilities only |
| `/sg` | Alias for `/security-guardian` |

---

## CLI Usage (without Claude)

After global install or building locally:

```bash
# Full scan
security-guardian

# Scan specific path
security-guardian --path /path/to/repo

# Changed files only
security-guardian --changed

# Dependencies only
security-guardian --dependencies

# Save report to file
security-guardian --output security-report.md

# JSON output
security-guardian --json

# Both markdown and JSON
security-guardian --both --output report
```

---

## Development & Build

```bash
# Install dependencies
npm install

# Build TypeScript
npm run build

# Run directly with ts-node
npm run scan

# Watch mode
npm run build:watch
```

---

## Packaging for Distribution

Run the included packaging script to create a portable zip:

```bash
./package-plugin.sh
```

This creates `security-guardian-plugin.zip` which you can share, commit, or distribute via your internal marketplace.

To use in another repo:

```bash
unzip security-guardian-plugin.zip -d ~/security-guardian-plugin
mkdir -p ~/.claude/commands
cp ~/security-guardian-plugin/.claude/commands/*.md ~/.claude/commands/
```

---

## Example Output

```
# 🛡️ Security Guardian Report

**Repository:** pandora-ecom-web
**Scan Date:** 11/03/2026, 09:14:22
**Duration:** 4.2s

════════════════════════════════════════════════════════════

## 📊 Summary

**Overall Risk: 🔴 CRITICAL** (score: 72/100)

| Severity  | Count |
|-----------|-------|
| 🔴 Critical | 1   |
| 🟠 High     | 3   |
| 🟡 Medium   | 5   |
| 🔵 Low      | 2   |
| ⚪ Info     | 0   |
| **Total**   | **11** |

- 🔑 **Secrets Found:** 2
- ⚖️ **License Risks:** 1
- 🔍 **Scanners Run:** 5
- 📁 **Files Scanned:** 1,842

════════════════════════════════════════════════════════════

## 📦 Dependency Vulnerabilities

### 🟠 HIGH — lodash

**Issue:** Prototype pollution
**Installed:** `4.17.15`
**Fixed in:** `4.17.21`
**CVE:** CVE-2021-23337

> 💡 **Fix:** Upgrade lodash to 4.17.21 or run `npm audit fix`.

════════════════════════════════════════════════════════════

## 🛡️ Code Security Issues

### SQL Injection (1)

#### 🔴 CRITICAL api/auth.ts:42

**Rule:** `sql-injection-string-concat`
**Issue:** Potential SQL injection via string concatenation

```
const result = db.query("SELECT * FROM users WHERE id = " + req.params.id);
```

> 💡 **Fix:** Use parameterised queries. Never concatenate user input into SQL strings.

════════════════════════════════════════════════════════════

## 🔑 Exposed Secrets

⚠️ **ACTION REQUIRED:** Rotate any exposed credentials immediately!

### 🔴 CRITICAL — AWS ACCESS KEY

**File:** `config/aws.js` (line 12)
**Type:** aws_access_key
**Match (redacted):** `AKIA****XAMPLE`

> 💡 **Fix:** Remove the secret from source code. Use environment variables or a secrets manager.

════════════════════════════════════════════════════════════

## ⚖️ License Risks

### 🔴 High Risk Licences

| Package | Licence | Commercial Use | Recommendation |
|---------|---------|----------------|----------------|
| `some-lib` | AGPL-3.0 | ❌ Restricted | Replace with MIT alternative. |

════════════════════════════════════════════════════════════

## 🚀 Recommended Actions

1. **URGENT:** Rotate 2 exposed credential(s) immediately.
2. Fix 1 critical dependency vulnerability. Run `npm audit fix`.
3. Remediate 1 critical code security issue before deploying.
4. Review 1 high-risk licence(s) with your legal team.
```

---

## Safety

This plugin is **read-only**. It will never:
- ❌ Modify any source files
- ❌ Run `npm audit fix` or `npm install`
- ❌ Commit or push changes
- ❌ Delete files
- ❌ Send data to external services

---

## CI Integration

Add to your pipeline to fail on critical findings:

```yaml
# GitHub Actions example
- name: Security Scan
  run: npx security-guardian --path . --output security-report.md
  # Exits with code 1 if critical vulnerabilities or secrets are found
```

---

## Licence

MIT — Free for commercial and personal use.
