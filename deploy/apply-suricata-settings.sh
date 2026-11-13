#!/usr/bin/env bash
# Puts this lab's Suricata settings in place; run it once, and again after an
# upgrade replaces suricata.yaml:
#
#     sudo deploy/apply-suricata-settings.sh
#
# - Alerts keep what was sent: the payload and the HTTP body as text
#   (payload-printable, http-body-printable).
# - The packets of the flows that raised alerts are kept as pcap files in
#   /var/log/suricata (pcap-log, conditional: alerts): 10 files of 100 MiB at
#   most, the oldest going first.
# - The Conficker P2P rules are off (deploy/suricata/disable.conf).
# - Its logs are no longer open to every user: root writes them, and only
#   this folder's owner (the collector and the dashboard) may read them too.
#
# suricata.yaml is backed up and the new one checked with suricata -T; the
# old one comes back if the check fails. Then the rules are updated without
# the Conficker ones and Suricata is restarted (output settings need it).
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run it with sudo: sudo $0" >&2
    exit 1
fi
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
owner="$(stat -c %U "$repo_dir")"
config=/etc/suricata/suricata.yaml
logs=/var/log/suricata
backup="$config.bak-$(date +%Y%m%d-%H%M%S)"

echo "== Backing up $config to $backup"
cp -p "$config" "$backup"

echo "== Alert payloads as text, and pcap files of the alerted flows"
python3 - "$config" <<'PYTHON'
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
lines = path.read_text().splitlines(keepends=True)

def uncomment(pattern):
    """The commented-out option the pattern names, switched on; already on is fine."""
    for index, line in enumerate(lines):
        match = re.match(rf"^(\s*)#\s*({pattern}.*)$", line.rstrip("\n"))
        if match:
            lines[index] = f"{match.group(1)}{match.group(2)}\n"
            return
        if re.match(rf"^\s*{pattern}", line):
            return
    sys.exit(f"!! {pattern!r} not found in {path}")

uncomment(r"payload-printable: yes")
uncomment(r"http-body-printable: yes")

# The pcap-log block: from "- pcap-log:" to the next output at its indent.
start = next(i for i, line in enumerate(lines) if re.match(r"^\s*- pcap-log:", line))
indent = len(lines[start]) - len(lines[start].lstrip())
end = next(
    (i for i in range(start + 1, len(lines))
     if lines[i].strip() and not lines[i].lstrip().startswith("#")
     and len(lines[i]) - len(lines[i].lstrip()) <= indent),
    len(lines),
)
wanted = {
    "enabled": "yes",
    "limit": "100 MiB",
    "max-files": "10",
    "conditional": "alerts",
}
for index in range(start + 1, end):
    match = re.match(r"^(\s*)#?\s*(enabled|limit|max-files|conditional):\s*([^#\n]*)(.*)$", lines[index])
    if match and match.group(2) in wanted and len(match.group(1)) == indent + 4:
        lines[index] = f"{match.group(1)}{match.group(2)}: {wanted.pop(match.group(2))}\n"
if wanted:
    sys.exit(f"!! pcap-log has no {', '.join(wanted)} line in {path}")
path.write_text("".join(lines))
PYTHON

echo "== Checking the settings (suricata -T, without rules)"
test_dir="$(mktemp -d)"
if ! suricata -T -c "$config" -S /dev/null -l "$test_dir" > "$test_dir/test.log" 2>&1; then
    echo "!! Suricata didn't accept them; the old settings are back. Its output:" >&2
    tail -n 20 "$test_dir/test.log" >&2
    cp -p "$backup" "$config"
    exit 1
fi
rm -rf "$test_dir"

echo "== The Conficker P2P rules off"
install -m 0644 "$repo_dir/deploy/suricata/disable.conf" /etc/suricata/disable.conf
# --no-test: with HOME_NET "any" its test fails and it would keep the old rules.
suricata-update --no-test --quiet

echo "== Logs readable by root and $owner only"
install -d /etc/systemd/system/suricata.service.d
install -m 0644 "$repo_dir/deploy/systemd/suricata.service.d/log-access.conf" \
    /etc/systemd/system/suricata.service.d/log-access.conf
systemctl daemon-reload
chmod 0750 "$logs"
find "$logs" -maxdepth 1 -type f -exec chmod 0640 {} +
setfacl -m "u:$owner:rx" "$logs"
setfacl -d -m "u:$owner:r" "$logs"
find "$logs" -maxdepth 1 -type f -exec setfacl -m "u:$owner:r" {} +

echo "== Restarting Suricata"
loaded_before="$(grep -c 'rules successfully loaded' "$logs/suricata.log" 2>/dev/null || true)"
systemctl restart suricata
# Loading the rules takes a minute or so; then the dashboard's count.
for _ in $(seq 1 60); do
    if [[ "$(grep -c 'rules successfully loaded' "$logs/suricata.log" 2>/dev/null || true)" -gt "${loaded_before:-0}" ]]; then
        break
    fi
    sleep 3
done
systemctl is-active suricata
cd "$repo_dir"
runuser -u "$owner" -- .venv/bin/python scripts/save_rule_counts.py --suricata-log \
    || echo "!! The rule count wasn't saved; run scripts/save_rule_counts.py --suricata-log later." >&2
runuser -u "$owner" -- env PYTHONPATH=src .venv/bin/python src/ids/build_rule_index.py > /dev/null \
    || echo "!! The rule index wasn't rebuilt; run src/ids/build_rule_index.py later." >&2
systemctl try-restart ids-dashboard
echo "== Done. The old settings: $backup"
