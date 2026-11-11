#!/usr/bin/env bash
# Installs the collector and the dashboard as systemd services for this
# folder, run as the user who calls sudo, so that they start at boot and
# restart after a crash; and the timer of the nightly database backup:
#
#     sudo deploy/install-services.sh
#
# Stop copies started by hand (Ctrl+C) first: two collectors would read
# the same logs and save their places in the same file.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run it with sudo: sudo $0" >&2
    exit 1
fi
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
run_user="${SUDO_USER:-root}"

for unit in ids-collector.service ids-dashboard.service ids-backup.service ids-backup.timer; do
    sed -e "s|@REPO_DIR@|$repo_dir|g" -e "s|@USER@|$run_user|g" \
        "$repo_dir/deploy/systemd/$unit" > "/etc/systemd/system/$unit"
    echo "Installed /etc/systemd/system/$unit (runs as $run_user)"
done
systemctl daemon-reload
systemctl enable --now ids-collector.service ids-dashboard.service ids-backup.timer
systemctl --no-pager --lines=0 status ids-collector.service ids-dashboard.service
