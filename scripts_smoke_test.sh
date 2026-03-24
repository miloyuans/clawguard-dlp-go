#!/usr/bin/env bash
set -euo pipefail

TOKEN="${1:-test-guard-token}"
BASE="${2:-http://127.0.0.1:18080}"

echo "[1] health"
curl -sS "$BASE/healthz"; echo

echo "[2] sanitize"
curl -sS "$BASE/v1/sanitize" \
  -H 'content-type: application/json' \
  -d '{"userId":"7997315413","text":"password=abc123 bearer eyJabc.def.ghi ip 10.0.0.1"}'
 echo

echo "[3] model-proxy unauthorized (expect 401)"
code=$(curl -s -o /tmp/cg_u.out -w '%{http_code}' "$BASE/v1/model-proxy" -H 'content-type: application/json' -d '{"userId":"u1","prompt":"hello"}')
echo "code=$code"

echo "[4] model-proxy authorized"
curl -sS "$BASE/v1/model-proxy" \
  -H 'content-type: application/json' \
  -H "X-Guard-Token: $TOKEN" \
  -d '{"userId":"7997315413","prompt":"AKIA1234567890ABCDE password=abc123 and 192.168.1.2"}'
 echo
