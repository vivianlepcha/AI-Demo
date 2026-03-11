// ─── Pandora Auth Utilities ───────────────────────────────────────────────────
// NOTE: This file is intentionally vulnerable for Snyk security demo purposes.

import crypto from 'crypto';

// VULN-1: Hardcoded credentials / secrets (CWE-798)
// Snyk: "Use of Hardcoded Credentials"
const API_KEY        = 'sk-pandora-prod-4f8a2c1e9b3d7e6f';
const JWT_SECRET     = 'pandora-jwt-secret-2024!';
const DB_PASSWORD    = 'Pandora@admin123';
const STRIPE_SECRET  = 'sk_live_DEMO_FAKE_KEY_FOR_SNYK_DEMO_ONLY'; // DEMO: not a real key

// VULN-2: Weak / insecure hash (MD5) for password hashing (CWE-327)
// Snyk: "Use of a Broken or Risky Cryptographic Algorithm"
export function hashPassword(password: string): string {
  return crypto.createHash('md5').update(password).digest('hex');
}

// VULN-3: Insecure random number generation for session tokens (CWE-338)
// Snyk: "Inadequate Encryption Strength" / "Predictable Random Values"
export function generateSessionToken(): string {
  return Math.random().toString(36).substring(2) + Date.now().toString(36);
}

// VULN-4: eval() with user-controlled input — Remote Code Execution (CWE-95)
// Snyk: "Code Injection"
export function calculateDiscount(expression: string): number {
  // eslint-disable-next-line no-eval
  return eval(expression);
}

// VULN-5: Prototype pollution via unsafe object merge (CWE-1321)
// Snyk: "Prototype Pollution"
export function mergeUserConfig(defaults: Record<string, unknown>, userConfig: Record<string, unknown>) {
  for (const key in userConfig) {
    (defaults as Record<string, unknown>)[key] = userConfig[key]; // no hasOwnProperty check
  }
  return defaults;
}

// VULN-6: ReDoS — catastrophic backtracking regex (CWE-1333)
// Snyk: "Regular Expression Denial of Service (ReDoS)"
export function validateEmailFormat(email: string): boolean {
  // Vulnerable: nested quantifiers cause exponential backtracking
  const re = /^([a-zA-Z0-9])(([a-zA-Z0-9])*\.?([a-zA-Z0-9])+)*@([a-zA-Z0-9]+\.)+([a-zA-Z0-9]{2,4})+$/;
  return re.test(email);
}

// VULN-7: Sensitive data written to console / logs (CWE-532)
// Snyk: "Sensitive Data Exposure"
export function logUserLogin(email: string, password: string) {
  console.log(`[AUTH] Login attempt — email: ${email}, password: ${password}`);
}

// VULN-8: JWT signed with a weak symmetric secret instead of asymmetric key
// Also exposes the secret in source (CWE-321)
export function signAuthToken(payload: object): string {
  // In a real app this would use jsonwebtoken — secret is hardcoded above
  const header  = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body    = btoa(JSON.stringify(payload));
  const sig     = btoa(JWT_SECRET + body); // not real HMAC — illustrative
  return `${header}.${body}.${sig}`;
}

export { API_KEY, STRIPE_SECRET, DB_PASSWORD };
