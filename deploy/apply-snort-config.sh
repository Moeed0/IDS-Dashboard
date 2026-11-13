#!/usr/bin/env bash
# Install deploy/snort/snort.lua as the live Snort config. It enables every
# registered rule (no rules disabled in ips.states) and Snort's built-in
# decoder and inspector rules, as wanted for the most alerts. Backs up the
# live config, validates the new one, and restarts Snort only if validation
# passes; restores the backup if either step fails. It also installs
# snort-lab's drop-in (afpacket, and --plugin-path for the shared-object
# rules). The SO rules and the OpenAppID detectors it loads come first, from
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

echo "== Installing snort-lab's drop-in"
sudo install -D -m 0644 "$PROJECT_DIR/deploy/systemd/snort-lab.service.d/daq-afpacket.conf" \
    /etc/systemd/system/snort-lab.service.d/daq-afpacket.conf
sudo systemctl daemon-reload

echo "== Backing up $LIVE_CONFIG to $BACKUP"
sudo cp "$LIVE_CONFIG" "$BACKUP"

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

echo "== Restarting $SERVICE"
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
