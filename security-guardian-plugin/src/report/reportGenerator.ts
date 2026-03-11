// ============================================================
// Security Guardian Plugin — Report Generator
// Produces a formatted Markdown security report
// ============================================================

import {
  SecurityReport,
  DependencyVulnerability,
  CodeSecurityIssue,
  SecretFinding,
  LicenseRisk,
  Severity,
  ReportSummary,
  ScannerResult,
} from '../types/findings';

// ─── Formatting Helpers ───────────────────────────────────────

const SEVERITY_EMOJI: Record<Severity, string> = {
  critical: '🔴',
  high: '🟠',
  medium: '🟡',
  low: '🔵',
  info: '⚪',
};

const RISK_LEVEL_EMOJI: Record<ReportSummary['riskLevel'], string> = {
  critical: '🔴 CRITICAL',
  high: '🟠 HIGH',
  medium: '🟡 MEDIUM',
  low: '🔵 LOW',
  pass: '✅ PASS',
};

function severityBadge(severity: Severity): string {
  return `${SEVERITY_EMOJI[severity]} ${severity.toUpperCase()}`;
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function padEnd(str: string, len: number): string {
  return str.length >= len ? str : str + ' '.repeat(len - str.length);
}

function divider(char = '─', len = 60): string {
  return char.repeat(len);
}

// ─── Section Renderers ────────────────────────────────────────

function renderSummaryTable(summary: ReportSummary): string {
  const lines: string[] = [];
  lines.push('## 📊 Summary');
  lines.push('');
  lines.push(`**Overall Risk: ${RISK_LEVEL_EMOJI[summary.riskLevel]}** (score: ${summary.riskScore}/100)`);
  lines.push('');
  lines.push('| Severity  | Count |');
  lines.push('|-----------|-------|');
  lines.push(`| 🔴 Critical | **${summary.critical}** |`);
  lines.push(`| 🟠 High     | **${summary.high}** |`);
  lines.push(`| 🟡 Medium   | **${summary.medium}** |`);
  lines.push(`| 🔵 Low      | ${summary.low} |`);
  lines.push(`| ⚪ Info     | ${summary.info} |`);
  lines.push(`| **Total**   | **${summary.totalFindings}** |`);
  lines.push('');
  lines.push(`- 🔑 **Secrets Found:** ${summary.secretsFound}`);
  lines.push(`- ⚖️ **License Risks:** ${summary.licenseRisks}`);
  lines.push(`- 🔍 **Scanners Run:** ${summary.scannersRun}`);
  lines.push(`- 📁 **Files Scanned:** ${summary.filesScanned.toLocaleString()}`);
  if (summary.scannersWithErrors > 0) {
    lines.push(`- ⚠️ **Scanners with Errors:** ${summary.scannersWithErrors}`);
  }
  return lines.join('\n');
}

function renderScannerStatus(results: ScannerResult[]): string {
  const lines: string[] = [];
  lines.push('## ⚙️ Scanner Status');
  lines.push('');
  lines.push('| Scanner | Status | Findings | Files | Duration |');
  lines.push('|---------|--------|----------|-------|----------|');

  for (const r of results) {
    const status = r.error
      ? '❌ Error'
      : r.skipped
      ? '⏭️ Skipped'
      : '✅ Done';
    const note = r.error
      ? ` (${r.error.substring(0, 40)}...)`
      : r.skipReason
      ? ` (${r.skipReason})`
      : '';
    lines.push(
      `| ${r.scanner} | ${status}${note} | ${r.findings.length} | ${r.scannedFiles} | ${formatDuration(r.durationMs)} |`,
    );
  }

  return lines.join('\n');
}

function renderDependencyVulnerabilities(
  vulns: DependencyVulnerability[],
): string {
  if (vulns.length === 0) return '';

  const lines: string[] = [];
  lines.push('## 📦 Dependency Vulnerabilities');
  lines.push('');

  // Sort by severity
  const order: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
  const sorted = [...vulns].sort(
    (a, b) => order.indexOf(a.severity) - order.indexOf(b.severity),
  );

  for (const v of sorted) {
    lines.push(`### ${severityBadge(v.severity)} — ${v.package}`);
    lines.push('');
    lines.push(`**Issue:** ${v.title}`);
    if (v.installedVersion) lines.push(`**Installed:** \`${v.installedVersion}\``);
    if (v.fixedVersion) lines.push(`**Fixed in:** \`${v.fixedVersion}\``);
    if (v.cve) lines.push(`**CVE:** [${v.cve}](https://nvd.nist.gov/vuln/detail/${v.cve})`);
    if (v.cwe) lines.push(`**CWE:** ${v.cwe}`);
    if (v.url) lines.push(`**Reference:** ${v.url}`);
    if (v.isDirect === false) lines.push(`**Type:** Transitive dependency`);
    if (v.path && v.path.length > 0) {
      lines.push(`**Path:** \`${v.path.join(' → ')}\``);
    }
    if (v.recommendation) {
      lines.push('');
      lines.push(`> 💡 **Fix:** ${v.recommendation}`);
    }
    lines.push('');
    lines.push(divider());
    lines.push('');
  }

  return lines.join('\n');
}

function renderCodeSecurityIssues(issues: CodeSecurityIssue[]): string {
  if (issues.length === 0) return '';

  const lines: string[] = [];
  lines.push('## 🛡️ Code Security Issues');
  lines.push('');

  const order: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
  const sorted = [...issues].sort(
    (a, b) => order.indexOf(a.severity) - order.indexOf(b.severity),
  );

  // Group by category
  const byCategory = new Map<string, CodeSecurityIssue[]>();
  for (const issue of sorted) {
    const cat = issue.ruleCategory;
    if (!byCategory.has(cat)) byCategory.set(cat, []);
    byCategory.get(cat)!.push(issue);
  }

  for (const [category, categoryIssues] of byCategory) {
    lines.push(`### ${category} (${categoryIssues.length})`);
    lines.push('');

    for (const issue of categoryIssues) {
      lines.push(`#### ${severityBadge(issue.severity)} ${issue.file}:${issue.line}`);
      lines.push('');
      lines.push(`**Rule:** \`${issue.rule}\``);
      lines.push(`**Issue:** ${issue.title}`);
      if (issue.snippet) {
        lines.push('');
        lines.push('```');
        lines.push(issue.snippet);
        lines.push('```');
      }
      if (issue.recommendation) {
        lines.push('');
        lines.push(`> 💡 **Fix:** ${issue.recommendation}`);
      }
      lines.push('');
    }

    lines.push(divider());
    lines.push('');
  }

  return lines.join('\n');
}

function renderSecretsFindings(secrets: SecretFinding[]): string {
  if (secrets.length === 0) return '';

  const lines: string[] = [];
  lines.push('## 🔑 Exposed Secrets');
  lines.push('');
  lines.push('> ⚠️ **ACTION REQUIRED:** Rotate any exposed credentials immediately!');
  lines.push('');

  const order: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
  const sorted = [...secrets].sort(
    (a, b) => order.indexOf(a.severity) - order.indexOf(b.severity),
  );

  for (const secret of sorted) {
    lines.push(`### ${severityBadge(secret.severity)} — ${secret.patternType.replace(/_/g, ' ').toUpperCase()}`);
    lines.push('');
    lines.push(`**File:** \`${secret.file}\` (line ${secret.line})`);
    lines.push(`**Type:** ${secret.patternType}`);
    if (secret.match) {
      lines.push(`**Match (redacted):** \`${secret.match}\``);
    }
    if (secret.lineContent) {
      lines.push('');
      lines.push('```');
      lines.push(secret.lineContent);
      lines.push('```');
    }
    lines.push('');
    lines.push(`> 💡 **Fix:** ${secret.recommendation}`);
    lines.push('');
    lines.push(divider());
    lines.push('');
  }

  return lines.join('\n');
}

function renderLicenseRisks(risks: LicenseRisk[]): string {
  if (risks.length === 0) return '';

  const lines: string[] = [];
  lines.push('## ⚖️ License Risks');
  lines.push('');

  const byRisk = {
    high: risks.filter((r) => r.riskLevel === 'high'),
    medium: risks.filter((r) => r.riskLevel === 'medium'),
    low: risks.filter((r) => r.riskLevel === 'low'),
  };

  if (byRisk.high.length > 0) {
    lines.push('### 🔴 High Risk Licences');
    lines.push('');
    lines.push('| Package | Licence | Commercial Use | Recommendation |');
    lines.push('|---------|---------|----------------|----------------|');
    for (const r of byRisk.high) {
      const commercial = r.commercial ? '✅ Allowed' : '❌ Restricted';
      lines.push(`| \`${r.package}\` | ${r.license} | ${commercial} | ${r.recommendation} |`);
    }
    lines.push('');
  }

  if (byRisk.medium.length > 0) {
    lines.push('### 🟠 Medium Risk Licences');
    lines.push('');
    lines.push('| Package | Licence | Commercial Use |');
    lines.push('|---------|---------|----------------|');
    for (const r of byRisk.medium) {
      const commercial = r.commercial ? '⚠️ Conditions Apply' : '❌ Restricted';
      lines.push(`| \`${r.package}\` | ${r.license} | ${commercial} |`);
    }
    lines.push('');
  }

  if (byRisk.low.length > 0) {
    lines.push('### 🔵 Low Risk Licences');
    lines.push('');
    lines.push('| Package | Licence |');
    lines.push('|---------|---------|');
    for (const r of byRisk.low) {
      lines.push(`| \`${r.package}\` | ${r.license} |`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

function renderRecommendations(report: SecurityReport): string {
  const lines: string[] = [];
  lines.push('## 🚀 Recommended Actions');
  lines.push('');

  const actions: Array<{ priority: number; text: string }> = [];

  if (report.findings.secrets.length > 0) {
    actions.push({
      priority: 1,
      text: `**URGENT:** Rotate ${report.findings.secrets.length} exposed credential(s) immediately. Run \`git filter-branch\` or use BFG Repo Cleaner to purge from history.`,
    });
  }

  const criticalDeps = report.findings.dependencyVulnerabilities.filter(
    (v) => v.severity === 'critical',
  );
  if (criticalDeps.length > 0) {
    actions.push({
      priority: 2,
      text: `Fix ${criticalDeps.length} critical dependency vulnerabilities. Run \`npm audit fix\` or manually upgrade affected packages.`,
    });
  }

  const criticalCode = report.findings.codeSecurityIssues.filter(
    (v) => v.severity === 'critical',
  );
  if (criticalCode.length > 0) {
    actions.push({
      priority: 3,
      text: `Remediate ${criticalCode.length} critical code security issues (injection, eval, etc.) before deploying.`,
    });
  }

  const highRiskLicences = report.findings.licenseRisks.filter(
    (r) => r.riskLevel === 'high',
  );
  if (highRiskLicences.length > 0) {
    actions.push({
      priority: 4,
      text: `Review ${highRiskLicences.length} high-risk licence(s) with your legal team before shipping.`,
    });
  }

  if (actions.length === 0) {
    lines.push('✅ No critical actions required. Continue with regular security hygiene.');
  } else {
    for (let i = 0; i < actions.length; i++) {
      lines.push(`${i + 1}. ${actions[i].text}`);
      lines.push('');
    }
  }

  return lines.join('\n');
}

// ─── Main Report Generator ────────────────────────────────────

export function generateMarkdownReport(report: SecurityReport): string {
  const sections: string[] = [];

  // Header
  sections.push('# 🛡️ Security Guardian Report');
  sections.push('');
  sections.push(`**Repository:** \`${report.repository}\``);
  sections.push(`**Scan Date:** ${new Date(report.scanDate).toLocaleString()}`);
  sections.push(`**Duration:** ${formatDuration(report.durationMs)}`);
  sections.push(`**Path:** \`${report.repoPath}\``);
  sections.push('');
  sections.push(divider('═', 60));
  sections.push('');

  // Summary
  sections.push(renderSummaryTable(report.summary));
  sections.push('');
  sections.push(divider('═', 60));
  sections.push('');

  // Scanner status
  sections.push(renderScannerStatus(report.scannerResults));
  sections.push('');
  sections.push(divider('═', 60));
  sections.push('');

  // Findings (only non-empty sections)
  const depSection = renderDependencyVulnerabilities(report.findings.dependencyVulnerabilities);
  if (depSection) {
    sections.push(depSection);
    sections.push(divider('═', 60));
    sections.push('');
  }

  const codeSection = renderCodeSecurityIssues(report.findings.codeSecurityIssues);
  if (codeSection) {
    sections.push(codeSection);
    sections.push(divider('═', 60));
    sections.push('');
  }

  const secretsSection = renderSecretsFindings(report.findings.secrets);
  if (secretsSection) {
    sections.push(secretsSection);
    sections.push(divider('═', 60));
    sections.push('');
  }

  const licenseSection = renderLicenseRisks(report.findings.licenseRisks);
  if (licenseSection) {
    sections.push(licenseSection);
    sections.push(divider('═', 60));
    sections.push('');
  }

  // Clean bill of health
  if (report.summary.totalFindings === 0) {
    sections.push('## ✅ All Clear!');
    sections.push('');
    sections.push('No security issues were detected in this repository. Great work! 🎉');
    sections.push('');
  }

  // Recommendations
  sections.push(renderRecommendations(report));
  sections.push('');
  sections.push(divider('─', 60));
  sections.push('');
  sections.push('*Generated by [Security Guardian Plugin](https://github.com/pandora-jewelry/security-guardian-plugin) — Read-only scan, no changes made.*');

  return sections.join('\n');
}

// ─── JSON Report ──────────────────────────────────────────────

export function generateJsonReport(report: SecurityReport): string {
  return JSON.stringify(report, null, 2);
}

// ─── Console-Friendly Summary ─────────────────────────────────

export function generateConsoleSummary(report: SecurityReport): string {
  const { summary } = report;
  const lines: string[] = [
    '',
    '╔══════════════════════════════════════════════════════════╗',
    `║         Security Guardian — ${report.repository.padEnd(28)}║`,
    '╚══════════════════════════════════════════════════════════╝',
    '',
    `Risk Level : ${RISK_LEVEL_EMOJI[summary.riskLevel]} (${summary.riskScore}/100)`,
    `Scan Time  : ${formatDuration(report.durationMs)}`,
    '',
    '  Critical : ' + summary.critical,
    '  High     : ' + summary.high,
    '  Medium   : ' + summary.medium,
    '  Low      : ' + summary.low,
    '',
    '  Secrets  : ' + summary.secretsFound,
    '  Licences : ' + summary.licenseRisks,
    '',
  ];

  return lines.join('\n');
}
