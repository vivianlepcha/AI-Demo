// ============================================================
// Security Guardian Plugin — Secret Scanner
// Pure Node.js implementation — no external CLI required
// ============================================================

import * as fs from 'fs';
import * as path from 'path';
import {
  SecretFinding,
  SecretPatternType,
  ScannerResult,
  ScanOptions,
  Severity,
} from '../types/findings';

// ─── Pattern Definitions ──────────────────────────────────────

interface SecretPattern {
  type: SecretPatternType;
  regex: RegExp;
  severity: Severity;
  description: string;
  redactMatch?: boolean;
}

const SECRET_PATTERNS: SecretPattern[] = [
  {
    type: 'aws_access_key',
    regex: /\bAKIA[0-9A-Z]{16}\b/,
    severity: 'critical',
    description: 'AWS Access Key ID detected',
  },
  {
    type: 'aws_secret_key',
    regex: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?/i,
    severity: 'critical',
    description: 'AWS Secret Access Key detected',
    redactMatch: true,
  },
  {
    type: 'private_key',
    regex: /-----BEGIN\s+(?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,
    severity: 'critical',
    description: 'Private key material detected',
  },
  {
    type: 'github_token',
    regex: /\bghp_[A-Za-z0-9]{36}\b|\bgho_[A-Za-z0-9]{36}\b|\bghs_[A-Za-z0-9]{36}\b/,
    severity: 'critical',
    description: 'GitHub personal access token detected',
  },
  {
    type: 'slack_token',
    regex: /\bxox[baprs]-[0-9A-Za-z]{10,48}\b/,
    severity: 'high',
    description: 'Slack API token detected',
  },
  {
    type: 'stripe_key',
    regex: /\b(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}\b/,
    severity: 'critical',
    description: 'Stripe API key detected',
  },
  {
    type: 'google_api_key',
    regex: /\bAIza[0-9A-Za-z\\-_]{35}\b/,
    severity: 'high',
    description: 'Google API key detected',
  },
  {
    type: 'jwt_token',
    regex: /\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b/,
    severity: 'medium',
    description: 'JWT token detected in source code',
  },
  {
    type: 'npm_token',
    regex: /\bnpm_[A-Za-z0-9]{36}\b/,
    severity: 'high',
    description: 'npm publish token detected',
  },
  {
    type: 'sendgrid_key',
    regex: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/,
    severity: 'high',
    description: 'SendGrid API key detected',
  },
  {
    type: 'twilio_key',
    regex: /\bSK[0-9a-fA-F]{32}\b/,
    severity: 'high',
    description: 'Twilio API key detected',
  },
  {
    type: 'database_url',
    regex: /(?:postgres|mysql|mongodb|redis|amqp):\/\/[^:\s]+:[^@\s]+@[^\s'"]+/i,
    severity: 'high',
    description: 'Database connection string with credentials detected',
    redactMatch: true,
  },
  {
    type: 'generic_api_key',
    regex: /(?:api[_-]?key|apikey)\s*[=:]\s*["']([A-Za-z0-9_\-]{20,})["']/i,
    severity: 'medium',
    description: 'Generic API key assignment detected',
    redactMatch: true,
  },
  {
    type: 'generic_secret',
    regex: /(?:secret|SECRET)\s*[=:]\s*["']([A-Za-z0-9_\-!@#$%^&*]{12,})["']/,
    severity: 'medium',
    description: 'Generic secret value detected',
    redactMatch: true,
  },
  {
    type: 'generic_password',
    regex: /(?:password|PASSWORD|passwd)\s*[=:]\s*["']([^"']{8,})["']/,
    severity: 'medium',
    description: 'Hardcoded password detected',
    redactMatch: true,
  },
  {
    type: 'ssh_key',
    regex: /-----BEGIN OPENSSH PRIVATE KEY-----/,
    severity: 'critical',
    description: 'OpenSSH private key detected',
  },
  {
    type: 'pgp_key',
    regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----/,
    severity: 'critical',
    description: 'PGP private key detected',
  },
];

// ─── Files & Directories to Scan / Ignore ─────────────────────

const SCAN_EXTENSIONS = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs',
  '.py', '.java', '.go', '.rb', '.php', '.cs',
  '.env', '.env.local', '.env.development', '.env.production',
  '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf',
  '.json', '.xml', '.sh', '.bash', '.zsh',
  '.properties', '.gradle', '.tf', '.hcl',
]);

const SKIP_DIRECTORIES = new Set([
  'node_modules', 'dist', 'build', '.git', 'coverage',
  '.nyc_output', 'vendor', '__pycache__', '.cache',
  'out', '.next', '.nuxt', 'target', '.gradle',
]);

const SKIP_BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg',
  '.woff', '.woff2', '.ttf', '.eot', '.otf',
  '.mp3', '.mp4', '.wav', '.mov', '.avi',
  '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.pptx',
  '.zip', '.tar', '.gz', '.rar', '.7z',
  '.exe', '.dll', '.so', '.dylib', '.bin',
  '.lock',
]);

const MAX_FILE_SIZE = 512 * 1024; // 512 KB

// ─── Helpers ──────────────────────────────────────────────────

function redact(value: string): string {
  if (value.length <= 8) return '****';
  return value.substring(0, 4) + '****' + value.substring(value.length - 4);
}

function shouldScanFile(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase();
  const base = path.basename(filePath).toLowerCase();

  if (SKIP_BINARY_EXTENSIONS.has(ext)) return false;

  // Always scan .env files regardless of extension
  if (base.startsWith('.env')) return true;
  if (base === '.npmrc' || base === '.netrc' || base === '.gitconfig') return true;

  // Scan known text extensions
  if (SCAN_EXTENSIONS.has(ext)) return true;

  return false;
}

function* walkDirectory(
  dir: string,
  changedFiles?: string[],
): Generator<string> {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      if (SKIP_DIRECTORIES.has(entry.name)) continue;
      yield* walkDirectory(fullPath, changedFiles);
    } else if (entry.isFile()) {
      if (changedFiles && !changedFiles.includes(fullPath)) continue;
      if (!shouldScanFile(fullPath)) continue;
      try {
        const stat = fs.statSync(fullPath);
        if (stat.size > MAX_FILE_SIZE) continue;
      } catch {
        continue;
      }
      yield fullPath;
    }
  }
}

// ─── Main Scanner ─────────────────────────────────────────────

export async function runSecretScanner(
  options: ScanOptions,
): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: SecretFinding[] = [];
  let scannedFiles = 0;

  // Deduplicate: track (file, line, type) to avoid duplicate hits
  const seen = new Set<string>();

  for (const filePath of walkDirectory(options.repoPath)) {
    scannedFiles++;
    let content: string;

    try {
      content = fs.readFileSync(filePath, 'utf-8');
    } catch {
      continue;
    }

    const lines = content.split('\n');
    const relPath = path.relative(options.repoPath, filePath);

    for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
      const line = lines[lineIdx];

      for (const pattern of SECRET_PATTERNS) {
        const match = line.match(pattern.regex);
        if (!match) continue;

        const key = `${relPath}:${lineIdx + 1}:${pattern.type}`;
        if (seen.has(key)) continue;
        seen.add(key);

        const rawMatch = match[1] || match[0];
        const safeMatch = pattern.redactMatch ? redact(rawMatch) : rawMatch;
        const safeLine = line.replace(rawMatch, redact(rawMatch));

        findings.push({
          scanner: 'secrets',
          severity: pattern.severity,
          title: pattern.description,
          description: `${pattern.description} in ${relPath} at line ${lineIdx + 1}`,
          file: relPath,
          line: lineIdx + 1,
          pattern: pattern.regex.source,
          patternType: pattern.type,
          match: safeMatch,
          lineContent: safeLine.trim(),
          recommendation: `Remove the secret from source code. Use environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault). Rotate the exposed credential immediately.`,
        });
      }
    }
  }

  return {
    scanner: 'secrets',
    findings,
    scannedFiles,
    durationMs: Date.now() - startTime,
  };
}
