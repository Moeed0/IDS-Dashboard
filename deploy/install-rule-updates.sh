#!/usr/bin/env bash
# Installs ids-rule-update.timer, which runs deploy/update-rules.sh every
# night at 04:15 (Suricata's rules every night, Snort's once a week), and
# keeps Snort's oinkcode for it in /etc/ids/oinkcode, which only root can
# read. The oinkcode is typed at a prompt and never shown:
#
#     sudo deploy/install-rule-updates.sh
#     sudo deploy/install-rule-updates.sh --new-oinkcode   # replace it
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run it with sudo: sudo $0" >&2
    exit 1
fi
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

install -d -m 700 /etc/ids
if [[ ! -s /etc/ids/oinkcode || "${1:-}" == "--new-oinkcode" ]]; then
    read -rsp "Snort oinkcode (from your snort.org account page; Enter to leave Snort's rules as they are): " code
    echo
    if [[ -n "$code" ]]; then
        (umask 077 && printf '%s\n' "$code" > /etc/ids/oinkcode)
        echo "Saved in /etc/ids/oinkcode (root only)"
    fi
    unset code
fi
install -d /var/lib/ids

for unit in ids-rule-update.service ids-rule-update.timer; do
    sed -e "s|@REPO_DIR@|$repo_dir|g" "$repo_dir/deploy/systemd/$unit" > "/etc/systemd/system/$unit"
    echo "Installed /etc/systemd/system/$unit"
done
systemctl daemon-reload
systemctl enable --now ids-rule-update.timer
systemctl list-timers ids-rule-update.timer --no-pager
echo
echo "To fetch now:  sudo systemctl start ids-rule-update   (what it did: journalctl -u ids-rule-update)"
