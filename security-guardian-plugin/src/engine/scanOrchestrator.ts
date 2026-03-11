// ============================================================
// Security Guardian Plugin — Scan Orchestrator
// Runs all scanners in parallel and aggregates results
// ============================================================

import * as path from 'path';
import { execSync } from 'child_process';
import {
  SecurityReport,
  ReportSummary,
  ScanOptions,
  ScannerResult,
  Finding,
  DependencyVulnerability,
  CodeSecurityIssue,
  SecretFinding,
  LicenseRisk,
  Severity,
} from '../types/findings';

import { runSnykScanner } from '../scanners/snykScanner';
import { runSemgrepScanner } from '../scanners/semgrepScanner';
import { runSecretScanner } from '../scanners/secretScanner';
import { runDependencyScanner } from '../scanners/dependencyScanner';
import { runLicenseScanner } from '../scanners/licenseScanner';

// ─── Changed Files Detection ──────────────────────────────────

function getChangedFiles(repoPath: string): string[] {
  try {
    const output = execSync('git diff --name-only HEAD', {
      cwd: repoPath,
      timeout: 10_000,
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const staged = execSync('git diff --cached --name-only', {
      cwd: repoPath,
      timeout: 10_000,
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const all = [...output.split('\n'), ...staged.split('\n')]
      .map((f) => f.trim())
      .filter(Boolean)
      .map((f) => path.resolve(repoPath, f));
    return [...new Set(all)];
  } catch {
    return [];
  }
}

function getRepoName(repoPath: string): string {
  try {
    const remote = execSync('git remote get-url origin', {
      cwd: repoPath,
      timeout: 5_000,
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    }).trim();
    // Extract repo name from URL
    const match = remote.match(/\/([^/]+?)(?:\.git)?$/);
    if (match) return match[1];
  } catch {
    // fall through
  }
  return path.basename(repoPath);
}

// ─── Risk Score Calculation ───────────────────────────────────

function calculateRiskScore(summary: Omit<ReportSummary, 'riskScore' | 'riskLevel'>): {
  score: number;
  level: ReportSummary['riskLevel'];
} {
  // Weighted scoring: critical=25, high=10, medium=3, low=1, secrets×30
  const score = Math.min(
    100,
    summary.critical * 25 +
      summary.high * 10 +
      summary.medium * 3 +
      summary.low * 1 +
      summary.secretsFound * 30,
  );

  let level: ReportSummary['riskLevel'];
  if (score >= 50 || summary.critical > 0) level = 'critical';
  else if (score >= 25 || summary.high > 0) level = 'high';
  else if (score >= 10 || summary.medium > 0) level = 'medium';
  else if (score > 0) level = 'low';
  else level = 'pass';

  return { score, level };
}

// ─── Summary Builder ──────────────────────────────────────────

function buildSummary(
  results: ScannerResult[],
  findings: SecurityReport['findings'],
): ReportSummary {
  const countBySeverity = (sevs: Severity[], all: Finding[]) =>
    all.filter((f) => sevs.includes(f.severity)).length;

  const allFindings: Finding[] = [
    ...findings.dependencyVulnerabilities,
    ...findings.codeSecurityIssues,
    ...findings.secrets,
    ...findings.licenseRisks,
  ];

  const base = {
    totalFindings: allFindings.length,
    critical: countBySeverity(['critical'], allFindings),
    high: countBySeverity(['high'], allFindings),
    medium: countBySeverity(['medium'], allFindings),
    low: countBySeverity(['low'], allFindings),
    info: countBySeverity(['info'], allFindings),
    secretsFound: findings.secrets.length,
    licenseRisks: findings.licenseRisks.length,
    scannersRun: results.filter((r) => !r.skipped).length,
    scannersWithErrors: results.filter((r) => !!r.error).length,
    filesScanned: results.reduce((sum, r) => sum + r.scannedFiles, 0),
    riskScore: 0,
    riskLevel: 'pass' as ReportSummary['riskLevel'],
  };

  const { score, level } = calculateRiskScore(base);
  return { ...base, riskScore: score, riskLevel: level };
}

// ─── Orchestrator ─────────────────────────────────────────────

export async function runSecurityScan(
  options: ScanOptions,
): Promise<SecurityReport> {
  const overallStart = Date.now();

  // Resolve changed files if needed
  let resolvedOptions = { ...options };
  if (options.changedFilesOnly) {
    const changed = getChangedFiles(options.repoPath);
    if (changed.length === 0) {
      console.warn('[SecurityGuardian] No changed files detected — scanning everything.');
      resolvedOptions.changedFilesOnly = false;
    }
  }

  // Build scanner list based on options
  const scanners = options.dependenciesOnly
    ? [
        { name: 'snyk' as const, fn: () => runSnykScanner(resolvedOptions) },
        { name: 'dependency' as const, fn: () => runDependencyScanner(resolvedOptions) },
      ]
    : [
        { name: 'snyk' as const, fn: () => runSnykScanner(resolvedOptions) },
        { name: 'semgrep' as const, fn: () => runSemgrepScanner(resolvedOptions) },
        { name: 'secrets' as const, fn: () => runSecretScanner(resolvedOptions) },
        { name: 'dependency' as const, fn: () => runDependencyScanner(resolvedOptions) },
        { name: 'license' as const, fn: () => runLicenseScanner(resolvedOptions) },
      ];

  // Filter skipped scanners
  const activeScanner = scanners.filter(
    (s) => !(options.skipScanners ?? []).includes(s.name),
  );

  // Run all in parallel
  const results: ScannerResult[] = await Promise.all(
    activeScanner.map(async ({ fn }) => {
      try {
        return await fn();
      } catch (err) {
        return {
          scanner: 'secrets' as const, // placeholder
          findings: [],
          scannedFiles: 0,
          durationMs: 0,
          error: err instanceof Error ? err.message : String(err),
        };
      }
    }),
  );

  // Segregate findings by type
  const dependencyVulnerabilities: DependencyVulnerability[] = [];
  const codeSecurityIssues: CodeSecurityIssue[] = [];
  const secrets: SecretFinding[] = [];
  const licenseRisks: LicenseRisk[] = [];

  for (const result of results) {
    for (const finding of result.findings) {
      switch (finding.scanner) {
        case 'snyk':
        case 'dependency':
          dependencyVulnerabilities.push(finding as DependencyVulnerability);
          break;
        case 'semgrep':
          codeSecurityIssues.push(finding as CodeSecurityIssue);
          break;
        case 'secrets':
          secrets.push(finding as SecretFinding);
          break;
        case 'license':
          licenseRisks.push(finding as LicenseRisk);
          break;
      }
    }
  }

  const findings = {
    dependencyVulnerabilities,
    codeSecurityIssues,
    secrets,
    licenseRisks,
  };

  const summary = buildSummary(results, findings);

  return {
    repository: getRepoName(options.repoPath),
    repoPath: options.repoPath,
    scanDate: new Date().toISOString(),
    durationMs: Date.now() - overallStart,
    summary,
    scannerResults: results,
    findings,
  };
}
