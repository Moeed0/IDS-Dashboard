#!/usr/bin/env bash
# Install deploy/snort/snort.lua as the live Snort config. It enables every
# registered rule (no rules disabled in ips.states) and Snort's built-in
# decoder and inspector rules, as wanted for the most alerts (only 112:1,
# the unicast ARP request, and 1:1384, the UPnP malformed advertisement,
# are suppressed). Backs up the
# live config, validates the new one, and restarts Snort only if validation
# passes; restores the backup if either step fails. It also installs
# snort-lab's drop-in (afpacket, and --plugin-path for the shared-object
# rules), with IDS_INTERFACE from .env as the capture card. The SO rules and the OpenAppID detectors it loads come first, from
# sudo deploy/update-rules.sh.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
NEW_CONFIG="$PROJECT_DIR/deploy/snort/snort.lua"
LIVE_CONFIG=/usr/local/etc/snort/snort.lua
BACKUP="$LIVE_CONFIG.bak-$(date +%Y%m%d-%H%M%S)"
SERVICE=snort-lab
SO_RULES=/usr/local/lib/snort/so_rules
DETECTORS=/usr/local/lib/openappid/odp

for needed in "$SO_RULES" "$DETECTORS"; do
    if [ ! -d "$needed" ]; then
        echo "!! $needed is missing: run sudo deploy/update-rules.sh first" >&2
        exit 1
    fi
done

# The capture card: IDS_INTERFACE in .env (the files in the repository say
# ens38, this lab's first VM).
IFACE="$(grep -E '^IDS_INTERFACE=' "$PROJECT_DIR/.env" 2>/dev/null | tail -n 1 | cut -d= -f2- || true)"
IFACE="${IFACE:-ens38}"

echo "== Installing snort-lab and its drop-in, capturing on $IFACE"
sed "s/-i ens38 /-i $IFACE /" "$PROJECT_DIR/deploy/systemd/snort-lab.service" \
    | sudo tee /etc/systemd/system/snort-lab.service > /dev/null
sudo install -d /etc/systemd/system/snort-lab.service.d
sed "s/-i ens38 /-i $IFACE /" "$PROJECT_DIR/deploy/systemd/snort-lab.service.d/daq-afpacket.conf" \
    | sudo tee /etc/systemd/system/snort-lab.service.d/daq-afpacket.conf > /dev/null
sudo install -d /var/log/snort
# Snort's logs (alert_json.txt, and the extractor's TLS connections) are
# readable by this folder's owner, who runs the collector. Snort creates a
# file readable by root only, but keeps an existing file's permissions, so
# each is made here first.
owner="$(stat -c %U "$PROJECT_DIR")"
sudo setfacl -m "u:$owner:rx" /var/log/snort
sudo setfacl -d -m "u:$owner:r" /var/log/snort
for log in /var/log/snort/alert_json.txt /var/log/snort/extractor_tls.json; do
    sudo touch "$log"
    sudo chmod 0640 "$log"
    sudo setfacl -m "u:$owner:r" "$log"
done
sudo systemctl daemon-reload

echo "== Backing up $LIVE_CONFIG to $BACKUP"
sudo cp "$LIVE_CONFIG" "$BACKUP"
# The local rules file snort.lua includes; deploy/install-local-rules.sh
# fills it.
if [ ! -e /usr/local/etc/snort/local.rules ]; then
    sudo touch /usr/local/etc/snort/local.rules
fi

echo "== Installing $NEW_CONFIG"
sudo install -m 0644 "$NEW_CONFIG" "$LIVE_CONFIG"

echo "== Validating the configuration (this loads all rules)"
if ! sudo snort -c "$LIVE_CONFIG" --plugin-path "$SO_RULES" -T > /tmp/snort-config-test.log 2>&1 \
    || ! grep -q "Snort successfully validated the configuration" /tmp/snort-config-test.log; then
    echo "!! Validation failed; restoring backup. Full output: /tmp/snort-config-test.log"
    sudo cp "$BACKUP" "$LIVE_CONFIG"
    exit 1
fi
grep -E "total rules loaded|successfully validated" /tmp/snort-config-test.log

echo "== Restarting $SERVICE (and starting it at boot)"
sudo systemctl enable --quiet "$SERVICE"
sudo systemctl restart "$SERVICE"
sleep 8
if ! systemctl is-active --quiet "$SERVICE"; then
    echo "!! $SERVICE did not start; restoring backup and restarting."
    sudo cp "$BACKUP" "$LIVE_CONFIG"
    sudo systemctl restart "$SERVICE"
    exit 1
fi
systemctl is-active "$SERVICE"
echo "== Done. Backup kept at $BACKUP"
