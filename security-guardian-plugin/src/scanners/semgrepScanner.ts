// ============================================================
// Security Guardian Plugin — Semgrep / Code Pattern Scanner
// Pure Node.js implementation — no external CLI required
// Detects common OWASP Top-10 and CWE issues via regex patterns
// ============================================================

import * as fs from 'fs';
import * as path from 'path';
import { CodeSecurityIssue, ScannerResult, ScanOptions, Severity } from '../types/findings';

// ─── Rule Definitions ─────────────────────────────────────────

interface CodeRule {
  id: string;
  category: string;
  severity: Severity;
  description: string;
  pattern: RegExp;
  fileExtensions?: string[];   // undefined = all code files
  recommendation: string;
  cwe?: string;
  owasp?: string;
  multiline?: boolean;
}

const CODE_RULES: CodeRule[] = [
  // ── SQL Injection ────────────────────────────────────────────
  {
    id: 'sql-injection-string-concat',
    category: 'SQL Injection',
    severity: 'critical',
    description: 'Potential SQL injection via string concatenation',
    pattern: /(?:query|execute|exec|sql|db\.run)\s*\(\s*["'`][^"'`]*["'`]\s*\+/i,
    cwe: 'CWE-89',
    owasp: 'A03:2021',
    recommendation: 'Use parameterised queries or a query builder (e.g., knex, TypeORM). Never concatenate user input into SQL strings.',
  },
  {
    id: 'sql-injection-template-literal',
    category: 'SQL Injection',
    severity: 'critical',
    description: 'Potential SQL injection via template literal with variable',
    pattern: /(?:query|execute|exec|sql)\s*\(\s*`[^`]*\$\{[^}]*(?:req\.|body\.|params\.|query\.)[^}]*\}[^`]*`/i,
    cwe: 'CWE-89',
    owasp: 'A03:2021',
    recommendation: 'Use parameterised queries. Template literals with user-controlled values are SQL injection vectors.',
  },

  // ── Command Injection ────────────────────────────────────────
  {
    id: 'command-injection-exec',
    category: 'Command Injection',
    severity: 'critical',
    description: 'Potential command injection via exec/execSync with dynamic input',
    pattern: /(?:exec|execSync|spawn|spawnSync|execFile)\s*\(\s*(?:`[^`]*\$\{|["'][^"']*["']\s*\+)/i,
    cwe: 'CWE-78',
    owasp: 'A03:2021',
    recommendation: 'Avoid passing user input to shell commands. Use spawn() with an array of arguments (no shell) or sanitise input with a strict allowlist.',
  },
  {
    id: 'command-injection-shell-true',
    category: 'Command Injection',
    severity: 'high',
    description: 'spawn() called with shell:true — enables shell injection',
    pattern: /spawn\s*\([^)]*shell\s*:\s*true/i,
    cwe: 'CWE-78',
    recommendation: 'Remove shell:true from spawn options. Use an argument array instead of a shell string.',
  },

  // ── Unsafe Deserialization ────────────────────────────────────
  {
    id: 'unsafe-deserialize',
    category: 'Insecure Deserialization',
    severity: 'high',
    description: 'Unsafe deserialisation detected (node-serialize / js-yaml.load)',
    pattern: /(?:unserialize|deserialize)\s*\(|yaml\.load\s*\([^,)]*(?:req\.|input|data)/i,
    cwe: 'CWE-502',
    owasp: 'A08:2021',
    recommendation: 'Use safeLoad for YAML. Avoid deserialising untrusted data. Prefer JSON.parse over eval-based deserialisation.',
  },
  {
    id: 'eval-usage',
    category: 'Code Injection',
    severity: 'critical',
    description: 'eval() usage detected — potential code injection',
    pattern: /\beval\s*\(/,
    fileExtensions: ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'],
    cwe: 'CWE-95',
    owasp: 'A03:2021',
    recommendation: 'Replace eval() with safer alternatives. Never pass user input to eval().',
  },
  {
    id: 'new-function-injection',
    category: 'Code Injection',
    severity: 'high',
    description: 'new Function() detected — potential code injection',
    pattern: /new\s+Function\s*\(/,
    cwe: 'CWE-95',
    recommendation: 'Avoid new Function(). It is equivalent to eval() and can execute arbitrary code.',
  },

  // ── Insecure Crypto ──────────────────────────────────────────
  {
    id: 'weak-hash-md5',
    category: 'Insecure Cryptography',
    severity: 'medium',
    description: 'MD5 hash usage detected — weak algorithm',
    pattern: /createHash\s*\(\s*['"]md5['"]\s*\)/i,
    cwe: 'CWE-328',
    recommendation: 'Replace MD5 with SHA-256 or SHA-3. MD5 is cryptographically broken.',
  },
  {
    id: 'weak-hash-sha1',
    category: 'Insecure Cryptography',
    severity: 'medium',
    description: 'SHA-1 hash usage detected — weak algorithm',
    pattern: /createHash\s*\(\s*['"]sha1['"]\s*\)/i,
    cwe: 'CWE-328',
    recommendation: 'Replace SHA-1 with SHA-256 or SHA-3. SHA-1 is deprecated for security use.',
  },
  {
    id: 'insecure-cipher-des',
    category: 'Insecure Cryptography',
    severity: 'high',
    description: 'DES/3DES cipher detected — insecure',
    pattern: /createCipher(?:iv)?\s*\(\s*['"](?:des|des-ede|des3|3des)['"]/i,
    cwe: 'CWE-326',
    recommendation: 'Replace DES/3DES with AES-256-GCM.',
  },
  {
    id: 'math-random-security',
    category: 'Insecure Randomness',
    severity: 'medium',
    description: 'Math.random() used in security-sensitive context',
    pattern: /Math\.random\s*\(\s*\)/,
    cwe: 'CWE-338',
    recommendation: 'Use crypto.randomBytes() or crypto.randomUUID() for security tokens.',
  },

  // ── XSS ──────────────────────────────────────────────────────
  {
    id: 'xss-innerhtml',
    category: 'Cross-Site Scripting (XSS)',
    severity: 'high',
    description: 'innerHTML assignment with dynamic content',
    pattern: /\.innerHTML\s*=\s*(?!["'])[^;]+/,
    cwe: 'CWE-79',
    owasp: 'A03:2021',
    recommendation: 'Use textContent or DOMPurify.sanitize() before setting innerHTML. Never inject untrusted content directly.',
  },
  {
    id: 'xss-dangerouslysetinnerhtml',
    category: 'Cross-Site Scripting (XSS)',
    severity: 'high',
    description: 'React dangerouslySetInnerHTML used with dynamic value',
    pattern: /dangerouslySetInnerHTML\s*=\s*\{\s*\{?\s*__html\s*:/,
    cwe: 'CWE-79',
    recommendation: 'Sanitise content with DOMPurify before using dangerouslySetInnerHTML.',
  },
  {
    id: 'document-write',
    category: 'Cross-Site Scripting (XSS)',
    severity: 'medium',
    description: 'document.write() usage — XSS vector',
    pattern: /document\.write\s*\(/,
    cwe: 'CWE-79',
    recommendation: 'Avoid document.write(). Use DOM APIs to create elements safely.',
  },

  // ── Path Traversal ───────────────────────────────────────────
  {
    id: 'path-traversal',
    category: 'Path Traversal',
    severity: 'high',
    description: 'Potential path traversal — user input passed to file system API',
    pattern: /(?:readFile|writeFile|readFileSync|writeFileSync|createReadStream|createWriteStream)\s*\(\s*(?:req\.|params\.|body\.|query\.)[^,)]+/i,
    cwe: 'CWE-22',
    owasp: 'A01:2021',
    recommendation: 'Use path.resolve() and validate that the resolved path starts with the expected base directory.',
  },

  // ── Insecure JWT ─────────────────────────────────────────────
  {
    id: 'jwt-none-algorithm',
    category: 'Authentication',
    severity: 'critical',
    description: 'JWT signed/verified with "none" algorithm',
    pattern: /(?:sign|verify)\s*\([^,]+,[^,]+,\s*\{[^}]*algorithm\s*:\s*['"]none['"]/i,
    cwe: 'CWE-347',
    recommendation: 'Never use the "none" JWT algorithm. Use RS256 or HS256 with a strong secret.',
  },
  {
    id: 'jwt-weak-secret',
    category: 'Authentication',
    severity: 'high',
    description: 'JWT signed with a short/hardcoded secret',
    pattern: /jwt\.sign\s*\([^,]+,\s*['"][^'"]{1,20}['"]/,
    cwe: 'CWE-521',
    recommendation: 'Use a cryptographically random secret of at least 256 bits stored in an environment variable.',
  },

  // ── SSRF / Open Redirect ─────────────────────────────────────
  {
    id: 'ssrf-user-controlled-url',
    category: 'Server-Side Request Forgery (SSRF)',
    severity: 'high',
    description: 'HTTP request to user-controlled URL',
    pattern: /(?:fetch|axios\.get|axios\.post|http\.get|https\.get|request)\s*\(\s*(?:req\.|params\.|body\.|query\.)[^,)]+/i,
    cwe: 'CWE-918',
    owasp: 'A10:2021',
    recommendation: 'Validate and allowlist URLs before making server-side HTTP requests.',
  },

  // ── Prototype Pollution ──────────────────────────────────────
  {
    id: 'prototype-pollution',
    category: 'Prototype Pollution',
    severity: 'high',
    description: 'Potential prototype pollution via merge/deep clone with user input',
    pattern: /Object\.assign\s*\(\s*(?:target|obj|{})\s*,\s*(?:req\.|body\.|params\.)/i,
    cwe: 'CWE-1321',
    recommendation: 'Use structured clone or a library that protects against prototype pollution (e.g., deepmerge with option isMergeableObject).',
  },

  // ── Insecure Cookies ────────────────────────────────────────
  {
    id: 'insecure-cookie-no-httponly',
    category: 'Insecure Cookie',
    severity: 'medium',
    description: 'Cookie set without httpOnly flag',
    pattern: /res\.cookie\s*\([^)]+\)\s*(?![^)]*httpOnly\s*:\s*true)/,
    cwe: 'CWE-614',
    recommendation: 'Set httpOnly: true and secure: true on all cookies.',
  },

  // ── NoSQL Injection ──────────────────────────────────────────
  {
    id: 'nosql-injection',
    category: 'NoSQL Injection',
    severity: 'high',
    description: 'Potential NoSQL injection — user input used directly in MongoDB query',
    pattern: /(?:find|findOne|findById|updateOne|deleteOne)\s*\(\s*(?:req\.|body\.|params\.|query\.)[^)]+\)/i,
    cwe: 'CWE-943',
    recommendation: 'Sanitise and validate all query inputs. Use mongoose schema validation.',
  },

  // ── Hardcoded Credentials ────────────────────────────────────
  {
    id: 'hardcoded-credentials-admin',
    category: 'Hardcoded Credentials',
    severity: 'high',
    description: 'Possible hardcoded admin credentials',
    pattern: /(?:username|user|login)\s*[=:]\s*['"](?:admin|root|administrator)['"].*(?:password|pass|pwd)\s*[=:]\s*['"][^'"]+['"]/i,
    cwe: 'CWE-798',
    recommendation: 'Remove hardcoded credentials. Use environment variables and a secrets manager.',
  },

  // ── ReDoS ────────────────────────────────────────────────────
  {
    id: 'redos-vulnerable-regex',
    category: 'Regular Expression DoS',
    severity: 'medium',
    description: 'Potentially catastrophic backtracking regex (ReDoS)',
    pattern: /new\s+RegExp\s*\(\s*(?:req\.|body\.|params\.|query\.)/i,
    cwe: 'CWE-1333',
    recommendation: 'Never compile user input as a regular expression. Validate or sanitise first.',
  },

  // ── Directory Listing ────────────────────────────────────────
  {
    id: 'express-serve-static-dotfiles',
    category: 'Information Disclosure',
    severity: 'low',
    description: 'express.static may expose dotfiles',
    pattern: /express\.static\s*\([^)]*\)/,
    recommendation: 'Set {dotfiles: "deny"} in express.static options to prevent exposing hidden files.',
  },
];

// ─── File Walking Helpers ─────────────────────────────────────

const CODE_EXTENSIONS = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs',
  '.py', '.java', '.go', '.rb', '.php', '.cs',
]);

const SKIP_DIRS = new Set([
  'node_modules', 'dist', 'build', '.git', 'coverage',
  '.nyc_output', 'vendor', '__pycache__', '.cache',
  'out', '.next', '.nuxt', 'target',
]);

const MAX_FILE_SIZE = 512 * 1024;

function* walkCodeFiles(dir: string): Generator<string> {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      yield* walkCodeFiles(fullPath);
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      if (!CODE_EXTENSIONS.has(ext)) continue;
      try {
        if (fs.statSync(fullPath).size > MAX_FILE_SIZE) continue;
      } catch {
        continue;
      }
      yield fullPath;
    }
  }
}

// ─── Main Scanner ─────────────────────────────────────────────

export async function runSemgrepScanner(
  options: ScanOptions,
): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: CodeSecurityIssue[] = [];
  let scannedFiles = 0;

  const seen = new Set<string>();

  for (const filePath of walkCodeFiles(options.repoPath)) {
    scannedFiles++;
    const ext = path.extname(filePath).toLowerCase();
    let content: string;

    try {
      content = fs.readFileSync(filePath, 'utf-8');
    } catch {
      continue;
    }

    const lines = content.split('\n');
    const relPath = path.relative(options.repoPath, filePath);

    for (const rule of CODE_RULES) {
      // Skip rules that don't apply to this file extension
      if (rule.fileExtensions && !rule.fileExtensions.includes(ext)) continue;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!rule.pattern.test(line)) continue;

        const key = `${relPath}:${i + 1}:${rule.id}`;
        if (seen.has(key)) continue;
        seen.add(key);

        // Extract a short snippet (trim whitespace)
        const snippet = line.trim().substring(0, 120);

        findings.push({
          scanner: 'semgrep',
          severity: rule.severity,
          title: rule.description,
          description: `[${rule.id}] ${rule.description}${rule.cwe ? ` (${rule.cwe})` : ''}${rule.owasp ? ` — OWASP ${rule.owasp}` : ''}`,
          file: relPath,
          line: i + 1,
          rule: rule.id,
          ruleCategory: rule.category,
          snippet,
          recommendation: rule.recommendation,
        });
      }
    }
  }

  return {
    scanner: 'semgrep',
    findings,
    scannedFiles,
    durationMs: Date.now() - startTime,
  };
}
