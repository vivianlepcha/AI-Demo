// ============================================================
// Security Guardian Plugin — Type Definitions
// ============================================================

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type ScannerName =
  | 'snyk'
  | 'semgrep'
  | 'secrets'
  | 'dependency'
  | 'license';

// ─── Base Finding ────────────────────────────────────────────

export interface BaseFinding {
  scanner: ScannerName;
  severity: Severity;
  title: string;
  description: string;
  file?: string;
  line?: number;
  recommendation?: string;
}

// ─── Dependency Vulnerability (Snyk / npm audit) ─────────────

export interface DependencyVulnerability extends BaseFinding {
  scanner: 'snyk' | 'dependency';
  package: string;
  installedVersion?: string;
  fixedVersion?: string;
  cve?: string;
  cwe?: string;
  url?: string;
  isDirect?: boolean;
  path?: string[];          // dependency chain
}

// ─── Code Security Issue (Semgrep) ───────────────────────────

export interface CodeSecurityIssue extends BaseFinding {
  scanner: 'semgrep';
  rule: string;
  ruleCategory: string;
  snippet?: string;
  column?: number;
}

// ─── Secret Finding ──────────────────────────────────────────

export interface SecretFinding extends BaseFinding {
  scanner: 'secrets';
  pattern: string;
  patternType: SecretPatternType;
  match?: string;           // redacted match
  lineContent?: string;     // redacted line content
}

export type SecretPatternType =
  | 'aws_access_key'
  | 'aws_secret_key'
  | 'private_key'
  | 'github_token'
  | 'slack_token'
  | 'stripe_key'
  | 'google_api_key'
  | 'jwt_token'
  | 'generic_api_key'
  | 'generic_secret'
  | 'generic_password'
  | 'database_url'
  | 'sendgrid_key'
  | 'twilio_key'
  | 'npm_token'
  | 'ssh_key'
  | 'pgp_key';

// ─── License Risk ─────────────────────────────────────────────

export interface LicenseRisk extends BaseFinding {
  scanner: 'license';
  package: string;
  license: string;
  riskLevel: 'high' | 'medium' | 'low';
  commercial?: boolean;
}

// ─── Union Type ───────────────────────────────────────────────

export type Finding =
  | DependencyVulnerability
  | CodeSecurityIssue
  | SecretFinding
  | LicenseRisk;

// ─── Scanner Result ───────────────────────────────────────────

export interface ScannerResult {
  scanner: ScannerName;
  findings: Finding[];
  scannedFiles: number;
  durationMs: number;
  error?: string;
  skipped?: boolean;
  skipReason?: string;
}

// ─── Scan Options ─────────────────────────────────────────────

export interface ScanOptions {
  repoPath: string;
  changedFilesOnly?: boolean;
  dependenciesOnly?: boolean;
  skipScanners?: ScannerName[];
  maxFileSizeBytes?: number;       // default 500 KB
  verbose?: boolean;
}

// ─── Aggregated Report ────────────────────────────────────────

export interface SecurityReport {
  repository: string;
  repoPath: string;
  scanDate: string;
  durationMs: number;
  summary: ReportSummary;
  scannerResults: ScannerResult[];
  findings: {
    dependencyVulnerabilities: DependencyVulnerability[];
    codeSecurityIssues: CodeSecurityIssue[];
    secrets: SecretFinding[];
    licenseRisks: LicenseRisk[];
  };
}

export interface ReportSummary {
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  secretsFound: number;
  licenseRisks: number;
  scannersRun: number;
  scannersWithErrors: number;
  filesScanned: number;
  riskScore: number;            // 0-100
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'pass';
}
