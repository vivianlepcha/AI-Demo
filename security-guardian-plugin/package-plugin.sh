#!/usr/bin/env bash
# ============================================================
# Security Guardian Plugin — Packaging Script
# Creates a distributable zip you can share or add to a marketplace
# Usage: ./package-plugin.sh
# ============================================================

set -euo pipefail

PLUGIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_NAME="security-guardian-plugin"
OUTPUT_ZIP="${PLUGIN_DIR}/../${PLUGIN_NAME}.zip"

echo "🛡️  Security Guardian — Packaging Plugin"
echo "📂 Source: ${PLUGIN_DIR}"
echo ""

# ── Optional: build TypeScript ────────────────────────────────
if command -v npx &>/dev/null && [ -f "${PLUGIN_DIR}/package.json" ]; then
  echo "⚙️  Building TypeScript..."
  cd "${PLUGIN_DIR}"
  npm install --quiet 2>/dev/null || true
  npx tsc 2>/dev/null && echo "✅ Build successful" || echo "⚠️  Build failed — including source only"
  cd - &>/dev/null
fi

# ── Create zip ────────────────────────────────────────────────
echo ""
echo "📦 Creating zip..."

cd "${PLUGIN_DIR}/.."

zip -r "${OUTPUT_ZIP}" "${PLUGIN_NAME}/" \
  --exclude "*/node_modules/*" \
  --exclude "*/.git/*" \
  --exclude "*/dist/*.js.map" \
  --exclude "*/coverage/*" \
  --exclude "*/.nyc_output/*" \
  --exclude "*/security-guardian-plugin.zip"

echo ""
echo "✅ Package created: ${OUTPUT_ZIP}"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📋 Install in another repo:"
echo ""
echo "  1. Unzip:"
echo "     unzip ${PLUGIN_NAME}.zip -d ~/${PLUGIN_NAME}"
echo ""
echo "  2. Copy commands globally:"
echo "     mkdir -p ~/.claude/commands"
echo "     cp ~/${PLUGIN_NAME}/.claude/commands/*.md ~/.claude/commands/"
echo ""
echo "  3. Open any repo in Claude Code and run:"
echo "     /security-guardian"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
