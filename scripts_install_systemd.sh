#!/usr/bin/env bash
set -euo pipefail

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN="$APP_DIR/build/clawguard"
ENV_FILE="/etc/clawguard.env"
UNIT_FILE="/etc/systemd/system/clawguard.service"

if [[ ! -x "$BIN" ]]; then
  echo "binary not found: $BIN"
  echo "run: $APP_DIR/scripts_build_release.sh"
  exit 1
fi

sudo mkdir -p /var/log/clawguard
sudo touch /var/log/clawguard/audit.log
sudo chmod 700 /var/log/clawguard
sudo chmod 600 /var/log/clawguard/audit.log

if [[ ! -f "$ENV_FILE" ]]; then
  sudo cp "$APP_DIR/production.env.example" "$ENV_FILE"
  sudo chmod 600 "$ENV_FILE"
  echo "created $ENV_FILE (please edit token/target)"
fi

sudo tee "$UNIT_FILE" >/dev/null <<EOF
[Unit]
Description=ClawGuard DLP Gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
EnvironmentFile=$ENV_FILE
ExecStart=$BIN
Restart=always
RestartSec=2
LimitNOFILE=65535
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ReadWritePaths=/var/log/clawguard

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now clawguard
sudo systemctl status clawguard --no-pager -l | sed -n '1,40p'
