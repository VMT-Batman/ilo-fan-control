#!/usr/bin/env bash
# iLO Fan Control -- installer / uninstaller.
#   Install:   sudo ./install.sh
#   Uninstall: sudo ./install.sh uninstall
set -euo pipefail

INSTALL_DIR="/srv/ilo-fan-control"
SERVICE_NAME="ilo-fan-control"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "Run this as root: sudo ./install.sh" >&2
        exit 1
    fi
}

validate_target() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ "$1" -ge 10 ] && [ "$1" -le 100 ]
}

install_deps() {
    echo "-- Installing dependencies..."
    if command -v apt-get >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y python3 python3-flask python3-requests python3-cheroot openssl
    elif command -v pip3 >/dev/null 2>&1; then
        echo "apt-get not found; installing via pip3 instead"
        pip3 install --quiet flask requests cheroot
    else
        echo "Could not find apt-get or pip3 -- install Python 3, flask, requests, and cheroot manually, then re-run." >&2
        exit 1
    fi
}

write_config() {
    echo
    echo "-- Let's set up your iLO connection (you can change any of this later"
    echo "   by editing $INSTALL_DIR/config.json or from the Settings page):"

    ILO_IP=""
    while [ -z "$ILO_IP" ]; do
        read -rp "   iLO IP address: " ILO_IP
        [ -z "$ILO_IP" ] && echo "   (required, try again)"
    done

    ILO_USER=""
    while [ -z "$ILO_USER" ]; do
        read -rp "   iLO username: " ILO_USER
        [ -z "$ILO_USER" ] && echo "   (required, try again)"
    done

    ILO_PASS=""
    while [ -z "$ILO_PASS" ]; do
        read -rsp "   iLO password: " ILO_PASS
        echo
        [ -z "$ILO_PASS" ] && echo "   (required, try again)"
    done

    TARGET=""
    while true; do
        read -rp "   Minimum fan percentage to enforce while online (10-100) [30]: " TARGET
        TARGET=${TARGET:-30}
        validate_target "$TARGET" && break
        echo "   (must be a whole number 10-100, try again)"
    done

    python3 - "$HERE/config.example.json" "$INSTALL_DIR/config.json" \
        "$ILO_IP" "$ILO_USER" "$ILO_PASS" "$TARGET" <<'PYEOF'
import json
import os
import re
import sys

example_path, out_path, ilo_ip, ilo_user, ilo_pass, target = sys.argv[1:7]

# config.example.json documents its optional keys as commented-out lines
# (// ...) with trailing commas throughout -- strip full-line comments and
# tolerate the resulting trailing comma before parsing. Kept in sync with
# fan_control.py's own _strip_json_comments().
text = open(example_path).read()
text = "\n".join(ln for ln in text.splitlines() if not ln.strip().startswith("//"))
text = re.sub(r",(\s*[}\]])", r"\1", text)
cfg = json.loads(text)
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
}

do_install() {
    require_root
    echo "== iLO Fan Control installer =="
    echo

    install_deps

    mkdir -p "$INSTALL_DIR/tls"
    cp "$HERE/fan_control.py" "$INSTALL_DIR/fan_control.py"
    chmod 755 "$INSTALL_DIR/fan_control.py"

    if [ -f "$INSTALL_DIR/config.json" ]; then
        echo "-- Existing config.json found at $INSTALL_DIR/config.json -- leaving it alone."
    else
        write_config
    fi

    cp "$HERE/ilo-fan-control.service" "$SERVICE_FILE"
    systemctl daemon-reload
    systemctl enable --now "$SERVICE_NAME"

    echo
    echo "-- Checking the iLO connection (a couple seconds)..."
    sleep 2
    if python3 "$INSTALL_DIR/fan_control.py" check; then
        echo "-- Connection OK."
    else
        echo "-- Could not confirm the iLO connection (see the error above)."
        echo "   Double-check ilo_ip / ilo_user / ilo_password in $INSTALL_DIR/config.json,"
        echo "   then: systemctl restart $SERVICE_NAME"
    fi

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
    echo
    echo "To remove everything later:  sudo ./install.sh uninstall"
}

do_uninstall() {
    require_root
    echo "== iLO Fan Control uninstaller =="
    echo

    echo "-- Stopping and disabling the service..."
    systemctl disable --now "$SERVICE_NAME" >/dev/null 2>&1 || true

    if [ -f "$SERVICE_FILE" ]; then
        rm -f "$SERVICE_FILE"
        systemctl daemon-reload
        echo "-- Removed $SERVICE_FILE"
    else
        echo "-- No systemd unit installed; nothing to remove there."
    fi

    if [ -d "$INSTALL_DIR" ]; then
        echo
        echo "   $INSTALL_DIR still contains config.json (your iLO password) and any"
        echo "   saved trend history."
        read -rp "   Delete it too? [y/N] " REPLY
        case "$REPLY" in
            [yY]*)
                rm -rf "$INSTALL_DIR"
                echo "-- Removed $INSTALL_DIR"
                ;;
            *)
                echo "-- Left $INSTALL_DIR in place"
                ;;
        esac
    fi

    echo
    echo "== Uninstalled =="
}

case "${1:-install}" in
    install) do_install ;;
    uninstall) do_uninstall ;;
    *)
        echo "Usage: $0 [install|uninstall]" >&2
        exit 1
        ;;
esac
