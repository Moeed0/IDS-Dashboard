#!/usr/bin/env bash
# Makes this VM's 9-10 GB of RAM go further, without changing what the IDS
# sees or alerts on. Run it once:
#
#     sudo deploy/optimize-memory.sh
#
# On 18 Nov 2026 systemd-oomd killed the Claude app and then the desktop's
# D-Bus (which logs you out, and looks like a restart) because memory ran
# short: Suricata ~0.8-1.3 GB, Snort ~0.6 GB, the dashboard ~0.25 GB, and the
# desktop, browser and Claude ~3-4 GB. What this does:
#
# - Compressed swap in RAM (zram, half the RAM, zstd). Rule tables and idle
#   desktop pages compress about 3:1, so swapping goes there first instead
#   of to the slow disk; the 4 GB swap file stays as the fallback.
# - systemd-oomd waits longer before killing the desktop session: memory
#   pressure above 80% (was 50%) for 60 s (was 20 s). It still steps in
#   before the VM locks up. Takes effect at your next login.
# - Suricata uses one capture thread (was 2): this lab sends about 3 packets
#   a second and none are dropped, and each thread keeps its own copy of the
#   rules' match state. Detection profile "low" with one shared pattern
#   matcher: the same 69,500 rules and the same alerts, loaded in half the
#   time (36 s, was 74 s), so the daily rule reload, when two copies of the
#   rules are in memory at once, is over sooner.
# - Printing (cups) is turned off: this VM has no printer.
# - The Talos rule-documentation download, if it isn't finished, runs as a
#   system service, so logging out or the desktop being killed no longer
#   stops it.
#
# Undo: sudo rm /etc/systemd/zram-generator.conf /etc/sysctl.d/90-ids-memory.conf \
#   /etc/systemd/system/user@.service.d/90-ids-oomd.conf /etc/systemd/oomd.conf.d/90-ids.conf
# then reboot; sudo systemctl enable --now cups cups-browsed; and the
# suricata.yaml backup this prints.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run it with sudo: sudo $0" >&2
    exit 1
fi
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
owner="$(stat -c %U "$repo_dir")"

echo "== Compressed swap in RAM (zram)"
if ! dpkg -s systemd-zram-generator > /dev/null 2>&1; then
    apt-get install -y systemd-zram-generator
fi
cat > /etc/systemd/zram-generator.conf <<'EOF'
# deploy/optimize-memory.sh: compressed swap in RAM, used before the swap file.
[zram0]
zram-size = ram / 2
compression-algorithm = zstd
swap-priority = 100
EOF
cat > /etc/sysctl.d/90-ids-memory.conf <<'EOF'
# deploy/optimize-memory.sh: with zram, swapping is cheap; swap idle pages
# before dropping the file cache the IDS logs and databases use.
vm.swappiness = 150
# zram has no seek time: read one page at a time.
vm.page-cluster = 0
EOF
sysctl -q --system
systemctl daemon-reload
systemctl restart systemd-zram-setup@zram0.service
swapon --show

echo "== systemd-oomd: kill the desktop session only on long, heavy memory pressure"
install -d /etc/systemd/system/user@.service.d /etc/systemd/oomd.conf.d
cat > /etc/systemd/system/user@.service.d/90-ids-oomd.conf <<'EOF'
# deploy/optimize-memory.sh: Ubuntu's default is 50%.
[Service]
ManagedOOMMemoryPressureLimit=80%
EOF
cat > /etc/systemd/oomd.conf.d/90-ids.conf <<'EOF'
# deploy/optimize-memory.sh: Ubuntu's default is 20 s.
[OOM]
DefaultMemoryPressureDurationSec=60s
EOF
systemctl daemon-reload
systemctl restart systemd-oomd

echo "== Suricata: one capture thread, detection profile low"
config=/etc/suricata/suricata.yaml
backup="$config.bak-$(date +%Y%m%d-%H%M%S)"
cp -p "$config" "$backup"
python3 - "$config" <<'PYTHON'
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
lines = path.read_text().splitlines(keepends=True)

def set_in(section, key, value):
    """key under the top-level section (its first occurrence), set to value."""
    start = next(i for i, line in enumerate(lines) if re.match(rf"^{section}:", line))
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if re.match(r"^\S", line):
            break
        match = re.match(rf"^(\s+){key}:\s*\S+", line)
        if match:
            lines[index] = f"{match.group(1)}{key}: {value}\n"
            return
    sys.exit(f"!! no {key} under {section}: in {path}")

set_in("af-packet", "threads", "1")
set_in("detect", "profile", "low")
set_in("detect", "sgh-mpm-context", "single")
path.write_text("".join(lines))
PYTHON
test_dir="$(mktemp -d)"
if ! suricata -T -c "$config" -S /dev/null -l "$test_dir" > "$test_dir/test.log" 2>&1; then
    echo "!! Suricata didn't accept them; the old settings are back. Its output:" >&2
    tail -n 20 "$test_dir/test.log" >&2
    cp -p "$backup" "$config"
    exit 1
fi
rm -rf "$test_dir"
loaded_before="$(grep -c 'rules successfully loaded' /var/log/suricata/suricata.log 2>/dev/null || true)"
systemctl restart suricata
for _ in $(seq 1 60); do
    if [[ "$(grep -c 'rules successfully loaded' /var/log/suricata/suricata.log 2>/dev/null || true)" -gt "${loaded_before:-0}" ]]; then
        break
    fi
    sleep 3
done
grep 'rules successfully loaded' /var/log/suricata/suricata.log | tail -n 1
systemctl is-active suricata

echo "== Printing off (no printer on this VM)"
systemctl disable --now cups-browsed.service cups.service cups.socket cups.path 2> /dev/null || true

talos="$repo_dir/data/intel/sources/talos"
if [[ -d $talos ]] && ! tail -n 1 "$talos/download.log" 2>/dev/null | grep -q '^{"output"'; then
    echo "== The Talos download, as a system service (it continues where it stopped)"
    pkill -u "$owner" -f download_talos_docs.py 2> /dev/null && sleep 2 || true
    systemctl stop talos-download.service 2> /dev/null || true
    systemctl reset-failed talos-download.service 2> /dev/null || true
    systemd-run --unit=talos-download --uid="$owner" --gid="$(id -g "$owner")" \
        --working-directory="$repo_dir" \
        --property=StandardOutput="append:$talos/download.log" \
        --property=StandardError="append:$talos/download.log" \
        "$repo_dir/.venv/bin/python" scripts/download_talos_docs.py
fi

echo "== Done. The old Suricata settings: $backup"
free -m
