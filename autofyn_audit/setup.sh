#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PNPM_BUNDLE="$REPO_DIR/pnpm/dist/pnpm.mjs"
VERDACCIO_BIN="$REPO_DIR/node_modules/verdaccio/bin/verdaccio"

echo "=== pnpm Security Audit Setup ==="

# Record git commit hash
git -C "$REPO_DIR" rev-parse HEAD > "$SCRIPT_DIR/.commit_hash"
COMMIT_HASH="$(cat "$SCRIPT_DIR/.commit_hash")"
echo "Commit hash: $COMMIT_HASH"

# Verify the bundle exists
if [[ ! -f "$PNPM_BUNDLE" ]]; then
  echo "ERROR: pnpm bundle not found at $PNPM_BUNDLE"
  exit 1
fi
echo "pnpm bundle verified: $PNPM_BUNDLE"

# Create verdaccio config
VERDACCIO_DIR="$SCRIPT_DIR/.verdaccio"
mkdir -p "$VERDACCIO_DIR/storage"

cat > "$VERDACCIO_DIR/config.yaml" <<'EOF'
storage: ./storage
auth:
  htpasswd:
    file: ./storage/htpasswd
    max_users: 100
uplinks: {}
packages:
  '@*/*':
    access: $all
    publish: $authenticated
    proxy: []
  '**':
    access: $all
    publish: $authenticated
    proxy: []
log: {type: stdout, format: pretty, level: warn}
server:
  keepAliveTimeout: 60
publish:
  allow_offline: true
EOF

# Kill any existing verdaccio
pkill -f "verdaccio.*pnpm-audit" 2>/dev/null || true
sleep 1

# Start verdaccio on port 4873
echo ""
echo "=== Starting verdaccio ==="
cd "$VERDACCIO_DIR"
node "$VERDACCIO_BIN" --config "$VERDACCIO_DIR/config.yaml" --listen http://0.0.0.0:4873 &
VERDACCIO_PID=$!
echo "$VERDACCIO_PID" > "$SCRIPT_DIR/.verdaccio_pid"
cd "$REPO_DIR"

echo "Verdaccio PID: $VERDACCIO_PID"
echo "Waiting for verdaccio to be ready..."

TIMEOUT=30
ELAPSED=0
until curl -sf http://localhost:4873/-/ping > /dev/null 2>&1; do
  if [[ $ELAPSED -ge $TIMEOUT ]]; then
    echo "ERROR: verdaccio did not become ready within ${TIMEOUT}s"
    kill "$VERDACCIO_PID" 2>/dev/null || true
    exit 1
  fi
  sleep 1
  ELAPSED=$((ELAPSED + 1))
done
echo "verdaccio is ready at http://localhost:4873"

# Create a verdaccio user
echo ""
echo "=== Creating verdaccio user ==="
VERDACCIO_TOKEN="$(curl -sf -X PUT http://localhost:4873/-/user/org.couchdb.user:audit \
  -H 'Content-Type: application/json' \
  -d '{"name":"audit","password":"audit123","email":"audit@test.com"}' \
  2>/dev/null | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("token",""))' 2>/dev/null)" || true

if [[ -n "$VERDACCIO_TOKEN" ]]; then
  echo "Verdaccio token obtained: ${VERDACCIO_TOKEN:0:20}..."
  echo "$VERDACCIO_TOKEN" > "$SCRIPT_DIR/.verdaccio_token"
else
  echo "WARNING: Could not obtain verdaccio token via API"
fi

echo ""
echo "=== Setup complete ==="
echo "  Commit: $COMMIT_HASH"
echo "  PNPM_BIN: node $PNPM_BUNDLE"
echo "  Verdaccio: http://localhost:4873 (PID: $VERDACCIO_PID)"
echo ""
echo "Run exploits with: bash $SCRIPT_DIR/run_all_exploits.sh"
