# Security Guardian — Full Repository Scan

Run a comprehensive security scan on the current repository and display a structured report.

## What This Command Does

Scans the repository using 5 security engines in parallel:

1. **Snyk** — Dependency vulnerabilities, CVEs, supply chain risks
2. **Semgrep** — Code security patterns (injection, XSS, weak crypto, etc.)
3. **Secret Scanner** — Exposed API keys, tokens, passwords, private keys
4. **Dependency Audit** — Outdated, deprecated, and vulnerable packages
5. **License Compliance** — GPL, AGPL, SSPL, and other risky licences

## Execution

Please perform a full security scan of this repository. Follow these steps:

### 1. Get repo path
```bash
REPO_PATH=$(pwd) && echo "Scanning: $REPO_PATH"
```

### 2. Try compiled plugin binary first
```bash
which security-guardian 2>/dev/null && \
  security-guardian --path "$REPO_PATH" --output .security-report.md && \
  cat .security-report.md
```

### 3. Try ts-node execution
If the binary is not available:
```bash
PLUGIN=$(find "$HOME" ~/.claude ~/Documents -name "security-guardian-plugin" -maxdepth 8 -type d 2>/dev/null | head -1)
[ -n "$PLUGIN" ] && cd "$PLUGIN" && npx ts-node src/commands/securityGuardian.ts --path "$REPO_PATH"
```

### 4. Run built-in fallback scan
If neither is available, run the built-in security checks using Bash tools:

**Secrets:**
```bash
echo "=== SECRETS SCAN ===" && \
grep -rn \
  -e "AKIA[0-9A-Z]\{16\}" \
  -e "-----BEGIN.*PRIVATE KEY" \
  -e "ghp_[A-Za-z0-9]\{36\}" \
  -e "xox[baprs]-[0-9A-Za-z]\{10,\}" \
  -e "sk_live_[0-9a-zA-Z]\{24,\}" \
  -e "AIza[0-9A-Za-z_-]\{35\}" \
  -e "npm_[A-Za-z0-9]\{36\}" \
  -e "SG\.[A-Za-z0-9_-]\{22\}\.[A-Za-z0-9_-]\{43\}" \
  --include="*.ts" --include="*.js" --include="*.jsx" --include="*.tsx" \
  --include="*.env*" --include="*.yaml" --include="*.yml" --include="*.json" \
  --exclude-dir=node_modules --exclude-dir=dist --exclude-dir=.git \
  --exclude-dir=build --exclude-dir=coverage \
  . 2>/dev/null | head -50 || echo "No secrets found"
```

**Dependencies:**
```bash
echo "=== DEPENDENCY VULNERABILITIES ===" && \
npm audit 2>/dev/null | tail -20 || echo "npm audit not available"
```

**Code Issues:**
```bash
echo "=== CODE SECURITY ISSUES ===" && \
grep -rn \
  -e "\beval\b\s*(" \
  -e "\.innerHTML\s*=" \
  -e "dangerouslySetInnerHTML" \
  -e "child_process.*exec\b.*\+\|child_process.*exec\b.*\`" \
  -e "createHash\(['\"]md5\|createHash\(['\"]sha1" \
  -e "Math\.random.*token\|Math\.random.*secret\|Math\.random.*key" \
  -e "new Function\s*(" \
  --include="*.ts" --include="*.js" --include="*.jsx" --include="*.tsx" \
  --exclude-dir=node_modules --exclude-dir=dist --exclude-dir=.git \
  . 2>/dev/null | head -50 || echo "No code issues found"
```

**Licenses:**
```bash
echo "=== LICENSE RISKS ===" && \
find node_modules -maxdepth 2 -name "package.json" \
  ! -path "*/.cache/*" 2>/dev/null | \
  xargs -I{} node -e "
    try {
      const p=require('{}');
      const l=typeof p.license==='string'?p.license:(p.license&&p.license.type)||'UNLICENSED';
      const risky=['GPL','AGPL','LGPL','SSPL','BUSL','EUPL'];
      if(risky.some(r=>l.toUpperCase().startsWith(r))) console.log(p.name+': '+l);
    } catch(e){}
  " 2>/dev/null | head -30 || echo "No risky licences found"
```

### 5. Compile and display results

After running the checks, compile all findings into the full Security Guardian Report format:

```
# 🛡️ Security Guardian Report

**Repository:** [repo name]
**Scan Date:** [date]

## 📊 Summary
[severity table]

## 📦 Dependency Vulnerabilities
[findings or ✅ None found]

## 🛡️ Code Security Issues
[findings or ✅ None found]

## 🔑 Exposed Secrets
[findings or ✅ None found]

## ⚖️ License Risks
[findings or ✅ None found]

## 🚀 Recommended Actions
[prioritised action items]
```

**Remember:** This is a read-only scan. Do not modify any files, run npm audit fix, or make any changes to the repository.
