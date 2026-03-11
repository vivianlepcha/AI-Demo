// ============================================================
// Security Guardian Plugin — License Compliance Scanner
// Reads node_modules/*/package.json — no external CLI required
// ============================================================

import * as fs from 'fs';
import * as path from 'path';
import { LicenseRisk, ScannerResult, ScanOptions, Severity } from '../types/findings';

// ─── License Risk Definitions ─────────────────────────────────

interface LicenseMeta {
  riskLevel: 'high' | 'medium' | 'low';
  severity: Severity;
  commercial: boolean;
  description: string;
  recommendation: string;
}

const LICENSE_RISK_MAP: Record<string, LicenseMeta> = {
  // ── High Risk (copyleft / viral) ──────────────────────────
  AGPL: {
    riskLevel: 'high',
    severity: 'high',
    commercial: false,
    description: 'GNU Affero GPL — strong copyleft, requires open-sourcing your server-side code',
    recommendation: 'Replace with an MIT/Apache-2.0 alternative or obtain a commercial licence.',
  },
  'AGPL-3.0': {
    riskLevel: 'high',
    severity: 'high',
    commercial: false,
    description: 'GNU Affero GPL v3 — strong copyleft, network use triggers share-alike obligation',
    recommendation: 'Replace with an MIT/Apache-2.0 alternative or obtain a commercial licence.',
  },
  'AGPL-3.0-only': {
    riskLevel: 'high',
    severity: 'high',
    commercial: false,
    description: 'AGPL-3.0-only — same risk as AGPL-3.0',
    recommendation: 'Replace with an MIT/Apache-2.0 alternative.',
  },
  GPL: {
    riskLevel: 'high',
    severity: 'high',
    commercial: false,
    description: 'GNU GPL — copyleft, may require open-sourcing your entire application',
    recommendation: 'Replace with an MIT/Apache-2.0 alternative or obtain a commercial exception.',
  },
  'GPL-2.0': {
    riskLevel: 'high',
    severity: 'high',
    commercial: false,
    description: 'GNU GPL v2 — copyleft licence',
    recommendation: 'Replace or obtain a commercial exception.',
  },
  'GPL-3.0': {
    riskLevel: 'high',
    severity: 'high',
    commercial: false,
    description: 'GNU GPL v3 — copyleft licence',
    recommendation: 'Replace or obtain a commercial exception.',
  },
  SSPL: {
    riskLevel: 'high',
    severity: 'high',
    commercial: false,
    description: 'Server Side Public Licence — not OSI approved, may require open-sourcing infrastructure',
    recommendation: 'Replace with an OSI-approved open-source alternative.',
  },
  'SSPL-1.0': {
    riskLevel: 'high',
    severity: 'high',
    commercial: false,
    description: 'SSPL v1 — same risk as SSPL',
    recommendation: 'Replace with an OSI-approved alternative.',
  },
  EUPL: {
    riskLevel: 'high',
    severity: 'high',
    commercial: false,
    description: 'European Union Public Licence — copyleft for modified distributions',
    recommendation: 'Review legal requirements with your legal team.',
  },
  Commons: {
    riskLevel: 'high',
    severity: 'high',
    commercial: false,
    description: 'Commons Clause — restricts commercial sale, not fully open source',
    recommendation: 'Obtain a commercial licence from the vendor.',
  },
  // ── Medium Risk (weak copyleft / attribution) ─────────────
  LGPL: {
    riskLevel: 'medium',
    severity: 'medium',
    commercial: true,
    description: 'GNU Lesser GPL — weak copyleft, modifying the library requires open-sourcing those changes',
    recommendation: 'Acceptable if used as an unmodified library. Consult legal if you plan to modify.',
  },
  'LGPL-2.1': {
    riskLevel: 'medium',
    severity: 'medium',
    commercial: true,
    description: 'LGPL v2.1 — weak copyleft',
    recommendation: 'Acceptable as unmodified dependency. Do not modify and redistribute.',
  },
  'LGPL-3.0': {
    riskLevel: 'medium',
    severity: 'medium',
    commercial: true,
    description: 'LGPL v3.0 — weak copyleft',
    recommendation: 'Acceptable as unmodified dependency.',
  },
  MPL: {
    riskLevel: 'medium',
    severity: 'medium',
    commercial: true,
    description: 'Mozilla Public Licence — file-level copyleft',
    recommendation: 'Acceptable if you keep MPL files separate and unmodified. Changes to MPL files must be open-sourced.',
  },
  'MPL-2.0': {
    riskLevel: 'medium',
    severity: 'medium',
    commercial: true,
    description: 'MPL v2.0 — file-level copyleft',
    recommendation: 'Changes to MPL files must be open-sourced.',
  },
  CDDL: {
    riskLevel: 'medium',
    severity: 'medium',
    commercial: true,
    description: 'Common Development and Distribution Licence — incompatible with GPL',
    recommendation: 'Review for compatibility with the rest of your dependency tree.',
  },
  // ── Low Risk (permissive, just attribution) ───────────────
  CC: {
    riskLevel: 'low',
    severity: 'info',
    commercial: true,
    description: 'Creative Commons — may have attribution or non-commercial restrictions',
    recommendation: 'Review the specific CC variant. CC-BY and CC-BY-SA are generally acceptable.',
  },
  'CC-BY-SA': {
    riskLevel: 'low',
    severity: 'low',
    commercial: true,
    description: 'CC-BY-SA — share-alike on derivative works',
    recommendation: 'Only use for non-code assets. Share-alike may propagate to derivatives.',
  },
  Artistic: {
    riskLevel: 'low',
    severity: 'low',
    commercial: true,
    description: 'Artistic Licence — permissive but with distribution conditions',
    recommendation: 'Generally acceptable. Review distribution conditions.',
  },
  CPOL: {
    riskLevel: 'medium',
    severity: 'medium',
    commercial: false,
    description: 'Code Project Open Licence — non-commercial restriction',
    recommendation: 'Not suitable for commercial products.',
  },
  'BUSL-1.1': {
    riskLevel: 'high',
    severity: 'high',
    commercial: false,
    description: 'Business Source Licence — commercial use restricted until change date',
    recommendation: 'Check the change date. May not be suitable for production commercial use.',
  },
  Proprietary: {
    riskLevel: 'high',
    severity: 'high',
    commercial: false,
    description: 'Proprietary / unknown licence — usage terms unclear',
    recommendation: 'Review with legal team. Obtain explicit permission from the package owner.',
  },
  UNLICENSED: {
    riskLevel: 'high',
    severity: 'high',
    commercial: false,
    description: 'No licence specified — all rights reserved by default',
    recommendation: 'Contact the package author for permission or replace with a licensed alternative.',
  },
};

// ─── Helpers ──────────────────────────────────────────────────

function normaliseLicense(license: string): string {
  return license?.trim().toUpperCase().replace(/\s+/g, '-') ?? 'UNKNOWN';
}

function matchLicenseRisk(license: string): LicenseMeta | null {
  const upper = normaliseLicense(license);

  // Exact match
  for (const [key, meta] of Object.entries(LICENSE_RISK_MAP)) {
    if (upper === key.toUpperCase()) return meta;
  }

  // Prefix match (e.g., "GPL-2.0-or-later" → "GPL-2.0")
  for (const [key, meta] of Object.entries(LICENSE_RISK_MAP)) {
    if (upper.startsWith(key.toUpperCase())) return meta;
  }

  return null;
}

function readPackageLicense(pkgPath: string): { name: string; license: string } | null {
  try {
    const raw = fs.readFileSync(pkgPath, 'utf-8');
    const pkg = JSON.parse(raw);
    const license =
      typeof pkg.license === 'string'
        ? pkg.license
        : typeof pkg.license?.type === 'string'
        ? pkg.license.type
        : 'UNLICENSED';

    return { name: pkg.name ?? path.basename(path.dirname(pkgPath)), license };
  } catch {
    return null;
  }
}

// ─── Main Scanner ─────────────────────────────────────────────

export async function runLicenseScanner(
  options: ScanOptions,
): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: LicenseRisk[] = [];
  let scannedFiles = 0;

  const nodeModulesPath = path.join(options.repoPath, 'node_modules');

  if (!fs.existsSync(nodeModulesPath)) {
    return {
      scanner: 'license',
      findings: [],
      scannedFiles: 0,
      durationMs: Date.now() - startTime,
      skipped: true,
      skipReason: 'node_modules not found — run npm install first',
    };
  }

  // Also check direct package.json deps for license field
  const ownPkgPath = path.join(options.repoPath, 'package.json');
  if (fs.existsSync(ownPkgPath)) {
    const own = readPackageLicense(ownPkgPath);
    if (own) {
      scannedFiles++;
      // Only flag if own package has a risky licence
      const meta = matchLicenseRisk(own.license);
      if (meta) {
        findings.push({
          scanner: 'license',
          severity: meta.severity,
          title: `Risky licence in ${own.name}: ${own.license}`,
          description: meta.description,
          file: 'package.json',
          package: own.name,
          license: own.license,
          riskLevel: meta.riskLevel,
          commercial: meta.commercial,
          recommendation: meta.recommendation,
        });
      }
    }
  }

  // Scan top-level node_modules packages
  let topLevelDirs: fs.Dirent[];
  try {
    topLevelDirs = fs.readdirSync(nodeModulesPath, { withFileTypes: true });
  } catch {
    return {
      scanner: 'license',
      findings,
      scannedFiles,
      durationMs: Date.now() - startTime,
      error: 'Failed to read node_modules',
    };
  }

  for (const entry of topLevelDirs) {
    if (!entry.isDirectory()) continue;

    let pkgJsonPath: string;

    if (entry.name.startsWith('@')) {
      // Scoped package — go one level deeper
      const scopeDir = path.join(nodeModulesPath, entry.name);
      let scopedEntries: fs.Dirent[];
      try {
        scopedEntries = fs.readdirSync(scopeDir, { withFileTypes: true });
      } catch {
        continue;
      }
      for (const scoped of scopedEntries) {
        if (!scoped.isDirectory()) continue;
        pkgJsonPath = path.join(scopeDir, scoped.name, 'package.json');
        if (!fs.existsSync(pkgJsonPath)) continue;

        scannedFiles++;
        const pkg = readPackageLicense(pkgJsonPath);
        if (!pkg) continue;

        const meta = matchLicenseRisk(pkg.license);
        if (!meta) continue;

        findings.push({
          scanner: 'license',
          severity: meta.severity,
          title: `Risky licence: ${pkg.name} (${pkg.license})`,
          description: meta.description,
          file: `node_modules/${entry.name}/${scoped.name}/package.json`,
          package: pkg.name,
          license: pkg.license,
          riskLevel: meta.riskLevel,
          commercial: meta.commercial,
          recommendation: meta.recommendation,
        });
      }
    } else {
      pkgJsonPath = path.join(nodeModulesPath, entry.name, 'package.json');
      if (!fs.existsSync(pkgJsonPath)) continue;

      scannedFiles++;
      const pkg = readPackageLicense(pkgJsonPath);
      if (!pkg) continue;

      const meta = matchLicenseRisk(pkg.license);
      if (!meta) continue;

      findings.push({
        scanner: 'license',
        severity: meta.severity,
        title: `Risky licence: ${pkg.name} (${pkg.license})`,
        description: meta.description,
        file: `node_modules/${entry.name}/package.json`,
        package: pkg.name,
        license: pkg.license,
        riskLevel: meta.riskLevel,
        commercial: meta.commercial,
        recommendation: meta.recommendation,
      });
    }
  }

  return {
    scanner: 'license',
    findings,
    scannedFiles,
    durationMs: Date.now() - startTime,
  };
}
