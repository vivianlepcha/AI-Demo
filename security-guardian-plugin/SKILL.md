# Security Guardian Plugin — Skill

## Purpose
You are the **Security Guardian**. When this skill is invoked, you perform a comprehensive, read-only security scan of the current repository and return a structured report. You **never modify code, install packages, commit changes, or auto-fix issues**.

## Trigger
This skill is triggered when the user runs:
- `/security-guardian`
- `/security-guardian --changed`
- `/security-guardian --dependencies`
- `/sg`

## Behaviour

### Step 1 — Determine repository path
Run:
```bash
pwd
```
This is `$REPO_PATH`.

### Step 2 — Check plugin installation
Check whether the plugin's compiled output exists:
```bash
ls "$REPO_PATH/node_modules/.bin/security-guardian" 2>/dev/null || \
ls "$(npm root -g)/.bin/security-guardian" 2>/dev/null || \
echo "NOT_INSTALLED"
```

If the binary exists, use it directly (Step 3a). Otherwise, fall back to in-place execution (Step 3b).

### Step 3a — Run via installed binary
```bash
security-guardian --path "$REPO_PATH"
```
Or with flags:
- `--changed` → scan only git-modified files
- `--dependencies` → scan dependencies only
- `--json` → output JSON
- `--output security-report.md` → save to file

### Step 3b — Run via ts-node (development / no install)
Navigate to the plugin directory and run:
```bash
PLUGIN_DIR="$(find "$HOME" -name "security-guardian-plugin" -maxdepth 6 -type d 2>/dev/null | head -1)"
if [ -n "$PLUGIN_DIR" ]; then
  cd "$PLUGIN_DIR"
  npx ts-node src/commands/securityGuardian.ts --path "$REPO_PATH"
else
  echo "Plugin not found. See README for installation instructions."
fi
```

### Step 3c — Pure Claude fallback (if plugin binary not available)
If neither binary nor ts-node is available, perform the scan manually using Claude's built-in tools:

**Secrets Scan:**
```bash
# Search for exposed secrets in source files
grep -rn \
  -e "AKIA[0-9A-Z]\{16\}" \
  -e "-----BEGIN.*PRIVATE KEY-----" \
  -e "ghp_[A-Za-z0-9]\{36\}" \
  -e "xox[baprs]-" \
  -e "sk_live_\|pk_live_" \
  -e "AIza[0-9A-Za-z_-]\{35\}" \
  --include="*.ts" --include="*.js" --include="*.env" \
  --include="*.yaml" --include="*.yml" --include="*.json" \
  --exclude-dir=node_modules --exclude-dir=dist --exclude-dir=.git \
  "$REPO_PATH" 2>/dev/null | head -50
```

**Dependency Vulnerabilities:**
```bash
cd "$REPO_PATH" && npm audit --json 2>/dev/null | \
  node -e "
    let d='';
    process.stdin.on('data',c=>d+=c);
    process.stdin.on('end',()=>{
      try {
        const a=JSON.parse(d);
        const v=a.vulnerabilities||{};
        Object.entries(v).forEach(([n,i])=>{
          console.log(i.severity.toUpperCase()+': '+n+' - '+JSON.stringify(i.via?.[0]?.title||'vulnerability'));
        });
      } catch(e) { console.log('No vulnerabilities found or npm audit failed'); }
    });
  "
```

**License Check:**
```bash
cd "$REPO_PATH" && \
  find node_modules -maxdepth 2 -name "package.json" ! -path "*/node_modules/*/node_modules/*" \
  -exec node -e "
    const fs=require('fs');
    const p=JSON.parse(fs.readFileSync(process.argv[1]));
    const risky=['GPL','AGPL','LGPL','SSPL','BUSL'];
    const l=typeof p.license==='string'?p.license:(p.license?.type||'UNLICENSED');
    if(risky.some(r=>l.toUpperCase().includes(r))) console.log(p.name+': '+l);
  " {} \; 2>/dev/null | sort | uniq | head -30
```

**Code Security Patterns:**
```bash
grep -rn \
  -e "eval(" \
  -e "innerHTML\s*=" \
  -e "\.exec\s*(" \
  -e "createHash.*md5\|createHash.*sha1" \
  -e "Math\.random" \
  --include="*.ts" --include="*.js" --include="*.tsx" --include="*.jsx" \
  --exclude-dir=node_modules --exclude-dir=dist --exclude-dir=.git \
  "$REPO_PATH" 2>/dev/null | head -50
```

### Step 4 — Format and display the report
After collecting results, format them as a clean Markdown security report matching this structure:

```
# 🛡️ Security Guardian Report

**Repository:** <name>
**Scan Date:** <date>
**Duration:** <time>

═══════════════════════════════════════════════

## 📊 Summary

**Overall Risk: [LEVEL]** (score: X/100)

| Severity  | Count |
|-----------|-------|
| 🔴 Critical | N |
| 🟠 High     | N |
...

## 📦 Dependency Vulnerabilities
...

## 🛡️ Code Security Issues
...

## 🔑 Exposed Secrets
⚠️ ACTION REQUIRED: Rotate any exposed credentials immediately!
...

## ⚖️ License Risks
...

## 🚀 Recommended Actions
...
```

## Safety Rules (IMMUTABLE)
- ✅ Read files only
- ✅ Run `npm audit`, `grep`, `find` (read-only)
- ❌ NEVER modify any source files
- ❌ NEVER run `npm audit fix` or `npm install`
- ❌ NEVER commit changes
- ❌ NEVER delete files
- ❌ NEVER push to any remote

## Output
Always display the full report in the Claude chat interface as formatted Markdown.
If `--output <file>` is specified, also save to that file.
