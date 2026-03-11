# Security Guardian — Changed Files Only

Scan only git-modified files for security issues (faster, ideal for pre-commit hooks).

## Execution

Run the security scan in `--changed` mode:

### 1. Get changed files
```bash
REPO_PATH=$(pwd)
CHANGED=$(git diff --name-only HEAD && git diff --cached --name-only)
echo "Changed files:"
echo "$CHANGED"
```

### 2. Run scan on changed files only
```bash
which security-guardian 2>/dev/null && \
  security-guardian --path "$REPO_PATH" --changed
```

Or via ts-node:
```bash
PLUGIN=$(find "$HOME" ~/.claude ~/Documents -name "security-guardian-plugin" -maxdepth 8 -type d 2>/dev/null | head -1)
[ -n "$PLUGIN" ] && cd "$PLUGIN" && \
  npx ts-node src/commands/securityGuardian.ts --path "$REPO_PATH" --changed
```

Or manually scan only the changed files for secrets and code issues — list them from git diff and grep only those files.

Display the same Security Guardian Report format, scoped to changed files only.

**Read-only. No modifications.**
