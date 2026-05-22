#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== pnpm Security Audit Teardown ==="

# Kill verdaccio
if [[ -f "$SCRIPT_DIR/.verdaccio_pid" ]]; then
  VERDACCIO_PID="$(cat "$SCRIPT_DIR/.verdaccio_pid")"
  if kill -0 "$VERDACCIO_PID" 2>/dev/null; then
    kill "$VERDACCIO_PID" 2>/dev/null || true
    echo "Killed verdaccio (PID: $VERDACCIO_PID)"
  fi
  rm -f "$SCRIPT_DIR/.verdaccio_pid"
fi

# Kill any lingering exploit server processes
pkill -f "server.mjs" 2>/dev/null || true
pkill -f "verdaccio.*config.yaml" 2>/dev/null || true

# Clean up temp files
rm -rf /tmp/pnpm-audit-* 2>/dev/null || true
rm -f /tmp/vuln2_captured_headers.json 2>/dev/null || true
rm -f /tmp/vuln3_captured_headers.json 2>/dev/null || true
rm -f /tmp/vuln4_pwned 2>/dev/null || true
rm -f /tmp/vuln5_postinstall_ran /tmp/vuln5_bin_executed 2>/dev/null || true

# Clean up verdaccio storage
rm -rf "$SCRIPT_DIR/.verdaccio" 2>/dev/null || true
rm -f "$SCRIPT_DIR/.verdaccio_token" 2>/dev/null || true
rm -f "$SCRIPT_DIR/.commit_hash" 2>/dev/null || true

# Remove Docker containers if any exist
docker rm -f pnpm-audit-verdaccio 2>/dev/null || true

echo "Teardown complete"
