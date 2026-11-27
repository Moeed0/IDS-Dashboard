#!/usr/bin/env bash
# Lets the dashboard turn rules off: a rule ticked as a false positive in
# the Overview's Top rules is suppressed in its engine within a minute or
# two, and unticking it turns it back on, with no command to run.
#
#     sudo deploy/install-rules-off.sh
#
# - deploy/rules-off/ids-rules-off.py goes to /usr/local/sbin/ids-rules-off,
#   owned by root: root runs that copy, never a file in this folder.
# - ids-rules-off.path watches the dashboard's list (IDS_RULES_OFF_FILE in
#   .env, .runtime/rules_off.json by default) and starts
#   ids-rules-off.service each time it is saved. The service reads the list
#   as data only (an engine, a GID and a SID per rule), suppresses those
#   rules (Suricata: its threshold file; Snort: suppress_dashboard.lua,
#   which deploy/snort/snort.lua reads), reloads the engine whose rules
#   changed (both keep capturing meanwhile) and writes how it went to
#   /var/lib/ids-rules-off/status.json, which the dashboard shows.
# - Snort's live config is brought up to date (deploy/apply-snort-config.sh)
#   when it doesn't read suppress_dashboard.lua yet.
#
# Anyone who can use the dashboard can then turn rules off: with
# IDS_API_REQUIRE_TOKEN=false, anyone who can reach its port.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run it with sudo: sudo $0" >&2
    exit 1
fi
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
owner="$(stat -c %U "$repo_dir")"
source_dir="$repo_dir/deploy/rules-off"

list="$(cd "$repo_dir" && runuser -u "$owner" -- env PYTHONPATH=src .venv/bin/python -c \
    'from ids.config import get_settings; print(get_settings().rules_off_file)')"
echo "== The dashboard's list: $list"
install -d -o "$owner" -g "$owner" "$(dirname "$list")"

echo "== /usr/local/sbin/ids-rules-off"
install -o root -g root -m 0755 "$source_dir/ids-rules-off.py" /usr/local/sbin/ids-rules-off
install -d -o root -g root -m 0755 /var/lib/ids-rules-off

if [[ -f /usr/local/etc/snort/snort.lua ]] && ! grep -q suppress_dashboard /usr/local/etc/snort/snort.lua; then
    echo "== Snort's config, which reads the rules turned off from the dashboard"
    "$repo_dir/deploy/apply-snort-config.sh"
fi

echo "== The watcher (ids-rules-off.path) and the service"
for unit in ids-rules-off.path ids-rules-off.service; do
    sed -e "s|@LIST@|$list|g" "$source_dir/$unit" > "/etc/systemd/system/$unit"
done
systemctl daemon-reload
systemctl enable --now ids-rules-off.path

echo "== Applying the list as it is now"
systemctl start ids-rules-off.service || true
cat /var/lib/ids-rules-off/status.json 2> /dev/null || true
echo "== Done: rules ticked in the dashboard's Top rules are turned off from now on."
