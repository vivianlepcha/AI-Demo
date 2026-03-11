// ─── Pandora Search API Route ──────────────────────────────────────────────────
// NOTE: This file is intentionally vulnerable for Snyk security demo purposes.

import { NextRequest, NextResponse } from 'next/server';
import { execSync } from 'child_process';

// VULN-1: OS Command Injection (CWE-78)
// Snyk: "Command Injection"
// Attacker can supply: ?q=charm; cat /etc/passwd
function runSearchIndexer(query: string) {
  // User-controlled input passed directly to shell
  const result = execSync(`grep -r "${query}" /var/app/search-index/`);
  return result.toString();
}

// VULN-2: XSS via unsanitised input reflected in HTML response (CWE-79)
// Snyk: "Cross-site Scripting (XSS)"
function buildSearchResultsHtml(query: string, results: string[]): string {
  // query is reflected without escaping — attacker injects <script>
  return `
    <html>
      <body>
        <h1>Results for: ${query}</h1>
        <ul>${results.map(r => `<li>${r}</li>`).join('')}</ul>
      </body>
    </html>
  `;
}

// GET /api/search?q=<query>
export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const query = searchParams.get('q') ?? '';

  // VULN-3: Unvalidated redirect — Open Redirect (CWE-601)
  // Snyk: "Open Redirect"
  const next = searchParams.get('next');
  if (next) {
    return NextResponse.redirect(next); // no allowlist — attacker can redirect to any URL
  }

  let indexerOutput = '';
  try {
    indexerOutput = runSearchIndexer(query);
  } catch {
    indexerOutput = 'index unavailable';
  }

  const html = buildSearchResultsHtml(query, [indexerOutput]);

  return new NextResponse(html, {
    headers: {
      'Content-Type': 'text/html',
      // VULN-4: Missing security headers (CWE-693)
      // No Content-Security-Policy, no X-Frame-Options, no X-Content-Type-Options
    },
  });
}
