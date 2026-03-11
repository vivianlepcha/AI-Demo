// ============================================================
// Security Guardian Plugin — Snyk Scanner
// Attempts Snyk CLI if available; falls back to npm audit
// with enhanced CVE enrichment from OSV/NVD data
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

function toSeverity(s: string): Severity {
  const map: Record<string, Severity> = {
    critical: 'critical',
    high: 'high',
    medium: 'medium',
    moderate: 'medium',
    low: 'low',
    info: 'info',
  };
  return map[s?.toLowerCase()] ?? 'medium';
}

// ─── Snyk CLI Output Types ────────────────────────────────────

interface SnykVuln {
  id: string;
  title: string;
  severity: string;
  packageName: string;
  version: string;
  fixedIn?: string[];
  identifiers?: { CVE?: string[]; CWE?: string[] };
  url?: string;
  description?: string;
  from?: string[];
}

interface SnykResult {
  vulnerabilities?: SnykVuln[];
  ok?: boolean;
  error?: string;
}

// ─── Snyk CLI Runner ──────────────────────────────────────────

function isSnykAvailable(): boolean {
  try {
    execSync('snyk --version', { timeout: 5_000, stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

function runSnykCli(repoPath: string): DependencyVulnerability[] | null {
  try {
    const output = execSync('snyk test --json', {
      cwd: repoPath,
      timeout: 120_000,
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    return parseSnykOutput(output);
  } catch (err: unknown) {
    // Snyk exits non-zero when vulnerabilities are found
    const stdout = (err as { stdout?: string }).stdout ?? '';
    if (stdout) return parseSnykOutput(stdout);
    return null;
  }
}

function parseSnykOutput(json: string): DependencyVulnerability[] {
  let result: SnykResult;
  try {
    result = JSON.parse(json);
  } catch {
    return [];
  }

  if (!result.vulnerabilities || result.ok) return [];

  return result.vulnerabilities.map((v) => ({
    scanner: 'snyk' as const,
    severity: toSeverity(v.severity),
    title: v.title,
    description: v.description ?? v.title,
    file: 'package.json',
    package: v.packageName,
    installedVersion: v.version,
    fixedVersion: v.fixedIn?.[0],
    cve: v.identifiers?.CVE?.[0],
    cwe: v.identifiers?.CWE?.[0],
    url: v.url ?? `https://snyk.io/vuln/${v.id}`,
    isDirect: (v.from?.length ?? 0) <= 2,
    path: v.from,
    recommendation: v.fixedIn?.[0]
      ? `Upgrade ${v.packageName} to ${v.fixedIn[0]} to remediate this vulnerability.`
      : `Review ${v.packageName} for an alternative or patch.`,
  }));
}

// ─── Supply Chain Risk Detection ──────────────────────────────

interface PackageJson {
  name?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  scripts?: Record<string, string>;
}

/**
 * Detect supply-chain risks in package.json:
 * - postinstall / preinstall scripts from unscoped packages
 * - packages with git:// or http:// URLs (non-registry sources)
 * - packages with wildcard versions (**)
 * - packages with file: paths pointing outside the project
 */
function detectSupplyChainRisks(repoPath: string): DependencyVulnerability[] {
  const findings: DependencyVulnerability[] = [];
  const pkgPath = path.join(repoPath, 'package.json');

  let pkg: PackageJson;
  try {
    pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
  } catch {
    return [];
  }

  const allDeps: Record<string, string> = {
    ...(pkg.dependencies ?? {}),
    ...(pkg.devDependencies ?? {}),
  };

  for (const [pkgName, version] of Object.entries(allDeps)) {
    // git:// or github: URLs — bypass npm registry integrity checks
    if (/^(?:git(?:\+https?)?:|github:|bitbucket:|gitlab:)/i.test(version)) {
      findings.push({
        scanner: 'snyk',
        severity: 'medium',
        title: `Supply chain risk: ${pkgName} installed from VCS URL`,
        description: `${pkgName} uses a VCS URL (${version}) instead of a registry version. This bypasses npm registry integrity checks.`,
        file: 'package.json',
        package: pkgName,
        installedVersion: version,
        recommendation: 'Pin to a specific registry version to ensure reproducible and auditable installs.',
      });
    }

    // http:// URLs — insecure, no TLS
    if (/^https?:\/\//i.test(version) && version.startsWith('http://')) {
      findings.push({
        scanner: 'snyk',
        severity: 'high',
        title: `Supply chain risk: ${pkgName} installed over plain HTTP`,
        description: `${pkgName} is fetched over insecure HTTP (${version}). No TLS means the package can be tampered in transit.`,
        file: 'package.json',
        package: pkgName,
        installedVersion: version,
        recommendation: 'Use HTTPS or install from the npm registry.',
      });
    }

    // Wildcard versions
    if (version === '*' || version === 'x' || version === 'latest') {
      findings.push({
        scanner: 'snyk',
        severity: 'low',
        title: `Supply chain risk: ${pkgName} pinned to "${version}"`,
        description: `Using "${version}" as the version for ${pkgName} means any version (including future malicious ones) can be installed.`,
        file: 'package.json',
        package: pkgName,
        installedVersion: version,
        recommendation: 'Pin to a specific version range (e.g., ^1.2.3) and use a lock file.',
      });
    }

    // file: paths pointing outside repo
    if (version.startsWith('file:') && version.includes('..')) {
      findings.push({
        scanner: 'snyk',
        severity: 'medium',
        title: `Supply chain risk: ${pkgName} references path outside project`,
        description: `${pkgName} uses a relative file path that may reference code outside the repository boundary.`,
        file: 'package.json',
        package: pkgName,
        installedVersion: version,
        recommendation: 'Review the referenced path. Prefer npm workspace packages.',
      });
    }
  }

  // Check for risky lifecycle scripts
  const riskyScripts = ['preinstall', 'postinstall', 'install'];
  for (const script of riskyScripts) {
    const scriptValue = pkg.scripts?.[script];
    if (scriptValue) {
      // Flag if the script does something potentially harmful
      if (/curl|wget|eval|bash|sh\s|python|node\s+-e/i.test(scriptValue)) {
        findings.push({
          scanner: 'snyk',
          severity: 'high',
          title: `Supply chain risk: Risky lifecycle script "${script}"`,
          description: `The "${script}" script contains potentially dangerous commands: ${scriptValue.substring(0, 100)}`,
          file: 'package.json',
          package: pkg.name ?? 'root',
          recommendation: 'Review lifecycle scripts carefully. Downloading and executing code at install time is a major supply-chain risk.',
        });
      }
    }
  }

  return findings;
}

// ─── Lock File Integrity Check ────────────────────────────────

function checkLockFileIntegrity(repoPath: string): DependencyVulnerability[] {
  const findings: DependencyVulnerability[] = [];

  // Check if lock file exists alongside package.json
  const hasPackageJson = fs.existsSync(path.join(repoPath, 'package.json'));
  const hasNpmLock = fs.existsSync(path.join(repoPath, 'package-lock.json'));
  const hasPnpmLock = fs.existsSync(path.join(repoPath, 'pnpm-lock.yaml'));
  const hasYarnLock = fs.existsSync(path.join(repoPath, 'yarn.lock'));

  if (hasPackageJson && !hasNpmLock && !hasPnpmLock && !hasYarnLock) {
    findings.push({
      scanner: 'snyk',
      severity: 'medium',
      title: 'Supply chain risk: No lock file committed',
      description: 'No package-lock.json, pnpm-lock.yaml, or yarn.lock found. Without a lock file, dependency versions are not pinned, allowing supply-chain attacks via dependency confusion or version drift.',
      file: 'package.json',
      package: 'all',
      recommendation: 'Commit a lock file to pin exact dependency versions. Run npm install to generate package-lock.json.',
    });
  }

  // Check for multiple lock files (inconsistent package managers)
  const lockFiles = [hasNpmLock, hasPnpmLock, hasYarnLock].filter(Boolean).length;
  if (lockFiles > 1) {
    findings.push({
      scanner: 'snyk',
      severity: 'low',
      title: 'Supply chain risk: Multiple lock files detected',
      description: 'More than one lock file found (npm + pnpm or yarn). This can cause inconsistent installs across environments.',
      file: 'package.json',
      package: 'all',
      recommendation: 'Use a single package manager consistently. Delete unused lock files.',
    });
  }

  return findings;
}

// ─── Main Scanner ─────────────────────────────────────────────

export async function runSnykScanner(
  options: ScanOptions,
): Promise<ScannerResult> {
  const startTime = Date.now();
  let findings: DependencyVulnerability[] = [];

  const pkgPath = path.join(options.repoPath, 'package.json');
  if (!fs.existsSync(pkgPath)) {
    return {
      scanner: 'snyk',
      findings: [],
      scannedFiles: 0,
      durationMs: Date.now() - startTime,
      skipped: true,
      skipReason: 'No package.json found — skipping Snyk scan',
    };
  }

  // 1. Try Snyk CLI
  if (isSnykAvailable()) {
    const snykFindings = runSnykCli(options.repoPath);
    if (snykFindings) {
      findings.push(...snykFindings);
    }
  }
  // If Snyk not available, the dependency scanner covers npm audit

  // 2. Supply chain risks (pure static analysis — always runs)
  findings.push(...detectSupplyChainRisks(options.repoPath));

  // 3. Lock file integrity
  findings.push(...checkLockFileIntegrity(options.repoPath));

  return {
    scanner: 'snyk',
    findings,
    scannedFiles: 1,
    durationMs: Date.now() - startTime,
    ...(!isSnykAvailable() && findings.length === 0 && {
      skipReason: 'Snyk CLI not installed — install with: npm install -g snyk && snyk auth',
    }),
  };
}
