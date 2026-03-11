// ─── Pandora User API Route ────────────────────────────────────────────────────
// NOTE: This file is intentionally vulnerable for Snyk security demo purposes.

import { NextRequest, NextResponse } from 'next/server';
import fs from 'fs';
import path from 'path';

// VULN-1: Hardcoded database credentials (CWE-798)
// Snyk: "Use of Hardcoded Credentials"
const DB_HOST     = 'prod-db.pandora-internal.net';
const DB_USER     = 'app_admin';
const DB_PASSWORD = 'Pandora@DB#2024!';
const INTERNAL_API_TOKEN = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.pandora_internal';

// VULN-2: SQL Injection via string concatenation (CWE-89)
// Snyk: "SQL Injection"
function buildUserQuery(userId: string): string {
  // Unsanitised user input concatenated directly into query string
  return `SELECT * FROM users WHERE id = '${userId}' AND status = 'active'`;
}

function buildOrderQuery(email: string): string {
  return `SELECT orders.* FROM orders JOIN users ON orders.user_id = users.id WHERE users.email = '${email}'`;
}

// GET /api/user?id=<id>&redirect=<url>&file=<filename>&email=<email>
export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const userId    = searchParams.get('id')       ?? '';
  const redirectUrl = searchParams.get('redirect') ?? '';
  const fileName  = searchParams.get('file')     ?? '';
  const email     = searchParams.get('email')    ?? '';

  // VULN-3: Server-Side Request Forgery — SSRF (CWE-918)
  // Snyk: "Server-Side Request Forgery (SSRF)"
  // Attacker can supply: ?redirect=http://169.254.169.254/latest/meta-data/
  if (redirectUrl) {
    const upstream = await fetch(redirectUrl, {
      headers: { Authorization: INTERNAL_API_TOKEN },
    });
    const data = await upstream.json();
    return NextResponse.json({ proxied: data });
  }

  // VULN-4: Path Traversal (CWE-22)
  // Snyk: "Path Traversal"
  // Attacker can supply: ?file=../../.env or ?file=../../../etc/passwd
  if (fileName) {
    const filePath = path.join('/var/app/uploads', fileName); // no normalisation / allowlist check
    const contents = fs.readFileSync(filePath, 'utf8');
    return NextResponse.json({ file: contents });
  }

  const userQuery  = buildUserQuery(userId);
  const orderQuery = buildOrderQuery(email);

  // VULN-5: Sensitive internal data returned to client (CWE-200)
  return NextResponse.json({
    query:       userQuery,
    orderQuery,
    dbHost:      DB_HOST,
    dbUser:      DB_USER,
    // password intentionally returned for demo
    dbPassword:  DB_PASSWORD,
  });
}

// POST /api/user  — insecure deserialization + mass-assignment
export async function POST(req: NextRequest) {
  // VULN-6: Insecure deserialization / mass-assignment (CWE-915)
  // Snyk: "Improperly Controlled Modification of Object Prototype Attributes"
  const body = await req.json();

  // No validation — any key in body is blindly spread onto the user object
  const user = Object.assign({ role: 'customer', verified: false }, body);

  // VULN-7: Prototype Pollution via Object.assign with untrusted input
  // body = { "__proto__": { "isAdmin": true } } would pollute Object.prototype
  return NextResponse.json({ user });
}
