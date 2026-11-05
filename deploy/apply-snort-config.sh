#!/usr/bin/env bash
# Install deploy/snort/snort.lua as the live Snort config. It enables every
# registered rule (no rules disabled in ips.states) and Snort's built-in
# decoder and inspector rules, as wanted for the most alerts. Backs up the
# live config, validates the new one, and restarts Snort only if validation
# passes; restores the backup if either step fails.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
NEW_CONFIG="$PROJECT_DIR/deploy/snort/snort.lua"
LIVE_CONFIG=/usr/local/etc/snort/snort.lua
BACKUP="$LIVE_CONFIG.bak-$(date +%Y%m%d-%H%M%S)"
SERVICE=snort-lab

echo "== Backing up $LIVE_CONFIG to $BACKUP"
sudo cp "$LIVE_CONFIG" "$BACKUP"

echo "== Installing $NEW_CONFIG"
sudo install -m 0644 "$NEW_CONFIG" "$LIVE_CONFIG"

echo "== Validating the configuration (this loads all rules)"
if ! sudo snort -c "$LIVE_CONFIG" -T > /tmp/snort-config-test.log 2>&1 \
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
