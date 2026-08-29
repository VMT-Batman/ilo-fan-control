#!/usr/bin/env bash
# iLO Fan Control -- installer.
# Run as root from inside a clone of this repo: sudo ./install.sh
set -euo pipefail

INSTALL_DIR="/srv/ilo-fan-control"
SERVICE_NAME="ilo-fan-control"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this as root: sudo ./install.sh" >&2
    exit 1
fi

echo "== iLO Fan Control installer =="
echo

echo "-- Installing dependencies..."
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y python3 python3-flask python3-requests python3-cheroot openssl
elif command -v pip3 >/dev/null 2>&1; then
    echo "apt-get not found; installing via pip3 instead"
    pip3 install --quiet flask requests cheroot
else
    echo "Could not find apt-get or pip3 -- install Python 3, flask, requests, and cheroot manually, then re-run." >&2
    exit 1
fi

mkdir -p "$INSTALL_DIR/tls"
cp "$HERE/fan_control.py" "$INSTALL_DIR/fan_control.py"
chmod 755 "$INSTALL_DIR/fan_control.py"

if [ -f "$INSTALL_DIR/config.json" ]; then
    echo "-- Existing config.json found at $INSTALL_DIR/config.json -- leaving it alone."
else
    echo
    echo "-- Let's set up your iLO connection (you can change any of this later"
    echo "   by editing $INSTALL_DIR/config.json or from the Settings page):"
    read -rp "   iLO IP address: " ILO_IP
    read -rp "   iLO username: " ILO_USER
    read -rsp "   iLO password: " ILO_PASS
    echo
    read -rp "   Minimum fan percentage to enforce while online (10-100) [30]: " TARGET
    TARGET=${TARGET:-30}

    python3 - "$HERE/config.example.json" "$INSTALL_DIR/config.json" \
        "$ILO_IP" "$ILO_USER" "$ILO_PASS" "$TARGET" <<'PYEOF'
import json
import os
import sys

example_path, out_path, ilo_ip, ilo_user, ilo_pass, target = sys.argv[1:7]
cfg = json.load(open(example_path))
cfg["ilo_ip"] = ilo_ip
cfg["ilo_user"] = ilo_user
cfg["ilo_password"] = ilo_pass
cfg["target_fan_percentage"] = int(target)

tmp = out_path + ".tmp"
with open(tmp, "w") as f:
    json.dump(cfg, f, indent=4)
os.chmod(tmp, 0o600)
os.replace(tmp, out_path)
PYEOF
    echo "-- Wrote $INSTALL_DIR/config.json (permissions locked to 600)"
fi

cp "$HERE/ilo-fan-control.service" /etc/systemd/system/ilo-fan-control.service
systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"

echo
echo "== Done =="
echo
echo "First run generates a random dashboard password automatically. Find it with:"
echo "    journalctl -u $SERVICE_NAME | grep 'Generated dashboard'"
echo
echo "...or set your own right now:"
echo "    python3 $INSTALL_DIR/fan_control.py set-password"
echo
echo "Dashboard: https://<this-machine-ip>:5000"
echo "(self-signed certificate -- your browser will warn once, that's expected)"
echo
echo "Check the service is healthy:"
echo "    systemctl status $SERVICE_NAME"
echo "    journalctl -u $SERVICE_NAME -f"
