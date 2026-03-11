# Security Guardian — Dependencies Only

Scan only dependency vulnerabilities and supply chain risks.

## Execution

```bash
REPO_PATH=$(pwd)
which security-guardian 2>/dev/null && \
  security-guardian --path "$REPO_PATH" --dependencies
```

Or via ts-node:
```bash
PLUGIN=$(find "$HOME" ~/.claude ~/Documents -name "security-guardian-plugin" -maxdepth 8 -type d 2>/dev/null | head -1)
[ -n "$PLUGIN" ] && cd "$PLUGIN" && \
  npx ts-node src/commands/securityGuardian.ts --path "$REPO_PATH" --dependencies
```

Or run directly:
```bash
cd "$REPO_PATH" && npm audit --json 2>/dev/null | node -e "
  let d='';
  process.stdin.on('data',c=>d+=c);
  process.stdin.on('end',()=>{
    try {
      const a=JSON.parse(d);
      const v=Object.values(a.vulnerabilities||{});
      console.log('Total vulnerabilities: '+v.length);
      v.sort((a,b)=>['critical','high','moderate','low'].indexOf(a.severity)-['critical','high','moderate','low'].indexOf(b.severity))
       .forEach(x=>console.log('['+x.severity.toUpperCase()+'] '+x.name));
    } catch(e) { console.log('No vulnerabilities data.'); }
  });
"
```

Display results in Security Guardian Report format (dependencies section only).

**Read-only. No npm audit fix. No modifications.**
