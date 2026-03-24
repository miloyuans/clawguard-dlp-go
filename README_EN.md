# ClawGuard DLP Gateway (Go) - English README

## Overview
ClawGuard is a pre-model DLP gateway that detects and redacts sensitive data before content is sent to an LLM.

## What it does
- Detects common sensitive data patterns (IP, email, bearer/JWT token, AWS AK-like keys, password fields, kubeconfig/private-key markers)
- Redacts content with placeholders
- Applies policy actions:
  - `ALLOW_REDACTED`
  - `BLOCK`
  - `LOCAL_ONLY` (reserved for policy extension)
- Writes audit logs without storing raw secrets
- Supports guard-token protected model proxy endpoint

## Project structure
- `cmd/server/main.go` - HTTP server
- `internal/dlp/` - detection and redaction engine
- `internal/policy/` - policy decisions
- `internal/audit/` - audit logger
- `internal/proxy/` - upstream forwarding helpers
- `build/clawguard` - compiled binary (if built)

## Endpoints
### Health
`GET /healthz`

### Redaction only
`POST /v1/sanitize`

Request example:
```bash
curl -s http://127.0.0.1:18080/v1/sanitize \
  -H 'content-type: application/json' \
  -d '{"userId":"u1","text":"my token is bearer abc... and ip 10.0.0.1"}'
```

### Guarded model proxy
`POST /v1/model-proxy`

Requires header:
- `X-Guard-Token: <your-token>`

## Environment variables
- `CLAWGUARD_LISTEN` (default `:18080`)
- `CLAWGUARD_AUDIT_PATH` (default `/tmp/clawguard_audit.log`)
- `CLAWGUARD_TOKEN` (required for model-proxy auth)
- `CLAWGUARD_MODEL_TARGET` (downstream model endpoint)
- `CLAWGUARD_DEFAULT_ACTION` (`ALLOW_REDACTED` by default)
- `CLAWGUARD_HIGH_ACTION` (`BLOCK` by default)
- `CLAWGUARD_UPSTREAM_BASE` (optional transparent upstream base, default `https://chatgpt.com`)

## Run locally
```bash
cd clawguard-dlp-go
CLAWGUARD_LISTEN=:18080 \
CLAWGUARD_AUDIT_PATH=/tmp/clawguard_audit.log \
CLAWGUARD_TOKEN='replace-with-strong-token' \
CLAWGUARD_MODEL_TARGET='http://127.0.0.1:8080/model' \
./build/clawguard
```

## Build
```bash
./scripts_build_release.sh
```

## systemd install
```bash
./scripts_install_systemd.sh
```

## Smoke test
```bash
./scripts_smoke_test.sh <token>
```

## Production rollout recommendation
1. Start in audit/observation mode
2. Enable `ALLOW_REDACTED` for normal traffic
3. Enforce `BLOCK` for high-sensitivity findings
4. Route all model traffic through `v1/model-proxy`

## Security notes
- Keep `/etc/clawguard.env` permission at `600`
- Keep audit logs restricted
- Rotate guard token regularly
- Use network ACLs so only trusted services can reach model targets
