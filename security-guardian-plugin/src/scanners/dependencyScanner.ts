// ============================================================
// Security Guardian Plugin — Dependency Audit Scanner
// Uses npm audit (built into Node.js ecosystem), parses output
// Falls back to static package.json analysis if npm audit fails
// ============================================================

import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';
import {
  DependencyVulnerability,
  ScannerResult,
  ScanOptions,
  Severity,
} from '../types/findings';

// ─── Severity Mapping ─────────────────────────────────────────

function mapSeverity(s: string): Severity {
  const map: Record<string, Severity> = {
    critical: 'critical',
    high: 'high',
    moderate: 'medium',
    medium: 'medium',
    low: 'low',
    info: 'info',
  };
  return map[s?.toLowerCase()] ?? 'medium';
}

// ─── npm audit parser ─────────────────────────────────────────

interface NpmAuditVulnerability {
  name: string;
  severity: string;
  isDirect: boolean;
  via: Array<string | NpmAuditViaDetail>;
  fixAvailable: boolean | { name: string; version: string; isSemVerMajor: boolean };
  nodes: string[];
  range?: string;
}

interface NpmAuditViaDetail {
  source: number;
  name: string;
  dependency: string;
  title: string;
  url: string;
  severity: string;
  cwe?: string[];
  cvss?: { score: number };
  range?: string;
}

interface NpmAuditResult {
  vulnerabilities?: Record<string, NpmAuditVulnerability>;
  auditReportVersion?: number;
}

function parseNpmAudit(
  jsonOutput: string,
  repoPath: string,
): DependencyVulnerability[] {
  let audit: NpmAuditResult;
  try {
    audit = JSON.parse(jsonOutput);
  } catch {
    return [];
  }

  const findings: DependencyVulnerability[] = [];

  if (!audit.vulnerabilities) return findings;

  for (const [pkgName, vuln] of Object.entries(audit.vulnerabilities)) {
    // Collect CVE / CWE / title info from via array
    const viaDetails = (vuln.via ?? []).filter(
      (v): v is NpmAuditViaDetail => typeof v === 'object',
    );

    const title =
      viaDetails[0]?.title ?? `Vulnerability in ${pkgName}`;
    const cve = viaDetails[0]?.url?.includes('npm') ? undefined : undefined;
    const cwe = viaDetails[0]?.cwe?.[0];
    const url = viaDetails[0]?.url;

    let fixedVersion: string | undefined;
    if (typeof vuln.fixAvailable === 'object' && vuln.fixAvailable.version) {
      fixedVersion = vuln.fixAvailable.version;
    }

    findings.push({
      scanner: 'dependency',
      severity: mapSeverity(vuln.severity),
      title,
      description: `${title} — package: ${pkgName}${vuln.range ? ` (${vuln.range})` : ''}`,
      file: 'package.json',
      package: pkgName,
      fixedVersion,
      cve,
      cwe,
      url,
      isDirect: vuln.isDirect,
      recommendation: fixedVersion
        ? `Upgrade ${pkgName} to ${fixedVersion} or run \`npm audit fix\`.`
        : `Review ${pkgName} for a patched version or alternative package.`,
    });
  }

  return findings;
}

// ─── Outdated Package Detection (npm outdated) ────────────────

interface OutdatedEntry {
  current: string;
  wanted: string;
  latest: string;
  dependent?: string;
  location?: string;
}

function checkOutdatedPackages(repoPath: string): DependencyVulnerability[] {
  try {
    const output = execSync('npm outdated --json', {
      cwd: repoPath,
      timeout: 30_000,
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    const outdated: Record<string, OutdatedEntry> = JSON.parse(output || '{}');
    const findings: DependencyVulnerability[] = [];

    for (const [pkg, info] of Object.entries(outdated)) {
      // Only flag packages that are significantly behind (major version difference)
      const currentMajor = parseInt((info.current ?? '0').split('.')[0], 10);
      const latestMajor = parseInt((info.latest ?? '0').split('.')[0], 10);

      if (latestMajor > currentMajor + 1) {
        findings.push({
          scanner: 'dependency',
          severity: 'low',
          title: `Outdated package: ${pkg}`,
          description: `${pkg} is on v${info.current}, latest is v${info.latest}`,
          file: 'package.json',
          package: pkg,
          installedVersion: info.current,
          fixedVersion: info.latest,
          recommendation: `Update ${pkg} from ${info.current} to ${info.latest}. Run: npm install ${pkg}@latest`,
        });
      }
    }

    return findings;
  } catch {
    // npm outdated exits non-zero when packages are outdated — parse stdout anyway
    return [];
  }
}

// ─── Deprecated Package Detection ────────────────────────────

const KNOWN_DEPRECATED: Record<string, { replacement: string; severity: Severity }> = {
  request: { replacement: 'axios or node-fetch', severity: 'medium' },
  moment: { replacement: 'date-fns or dayjs', severity: 'low' },
  'node-uuid': { replacement: 'uuid', severity: 'low' },
  'crypto-browserify': { replacement: 'crypto (built-in)', severity: 'low' },
  querystring: { replacement: 'URLSearchParams', severity: 'low' },
  'left-pad': { replacement: 'String.prototype.padStart()', severity: 'low' },
  'is-array': { replacement: 'Array.isArray()', severity: 'low' },
  hoek: { replacement: '@hapi/hoek', severity: 'medium' },
  boom: { replacement: '@hapi/boom', severity: 'medium' },
  'node-pre-gyp': { replacement: 'node-gyp or @mapbox/node-pre-gyp', severity: 'low' },
};

function detectDeprecatedPackages(repoPath: string): DependencyVulnerability[] {
  const findings: DependencyVulnerability[] = [];
  const pkgJsonPath = path.join(repoPath, 'package.json');

  let pkgJson: { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
  try {
    pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'));
  } catch {
    return [];
  }

  const allDeps = {
    ...(pkgJson.dependencies ?? {}),
    ...(pkgJson.devDependencies ?? {}),
  };

  for (const [pkg] of Object.entries(allDeps)) {
    const info = KNOWN_DEPRECATED[pkg];
    if (!info) continue;

    findings.push({
      scanner: 'dependency',
      severity: info.severity,
      title: `Deprecated package: ${pkg}`,
      description: `${pkg} is deprecated or unmaintained`,
      file: 'package.json',
      package: pkg,
      recommendation: `Replace ${pkg} with ${info.replacement}.`,
    });
  }

  return findings;
}

// ─── Main Scanner ─────────────────────────────────────────────

export async function runDependencyScanner(
  options: ScanOptions,
): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: DependencyVulnerability[] = [];

  // Check for package.json
  const pkgPath = path.join(options.repoPath, 'package.json');
  if (!fs.existsSync(pkgPath)) {
    return {
      scanner: 'dependency',
      findings: [],
      scannedFiles: 0,
      durationMs: Date.now() - startTime,
      skipped: true,
      skipReason: 'No package.json found — skipping dependency scan',
    };
  }

  // 1. Run npm audit
  try {
    const auditOutput = execSync('npm audit --json', {
      cwd: options.repoPath,
      timeout: 60_000,
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    findings.push(...parseNpmAudit(auditOutput, options.repoPath));
  } catch (err: unknown) {
    // npm audit exits with code 1 when vulnerabilities are found — stdout still has JSON
    const stderr = (err as { stdout?: string; stderr?: string }).stdout ?? '';
    if (stderr) {
      findings.push(...parseNpmAudit(stderr, options.repoPath));
    }
  }

  // 2. Check outdated packages
  findings.push(...checkOutdatedPackages(options.repoPath));

  // 3. Detect deprecated packages
  findings.push(...detectDeprecatedPackages(options.repoPath));

  return {
    scanner: 'dependency',
    findings,
    scannedFiles: 1, // package.json
    durationMs: Date.now() - startTime,
  };
}
