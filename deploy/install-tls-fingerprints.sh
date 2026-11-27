#!/usr/bin/env bash
# Puts the TLS fingerprint rules into Suricata (deploy/suricata/tls-fingerprints/):
#
#     sudo deploy/install-tls-fingerprints.sh
#
# Run it again after changing a known-bad list (known-bad-ja4.txt,
# known-bad-ja3.txt, known-bad-ja3s.txt there). deploy/apply-suricata-settings.sh
# runs it too, with --no-restart, and restarts Suricata itself.
#
# - The rules and their Lua script go to /etc/suricata/rules/ as
#   tls-fingerprints.rules and tls-fingerprints.lua, and the rules file is
#   added to Suricata's rule-files when it isn't there.
# - Each known-bad list is checked (one fingerprint per line, "#" starts a
#   note) and written as the dataset file Suricata loads, beside the rules:
#   tls-fingerprints-bad-ja4.lst, -ja3.lst, -ja3s.lst.
# - /var/lib/suricata/data, where Suricata keeps the fingerprints it has seen
#   (tls-ja4-seen.lst, tls-device-clients.lst) when it stops, is made.
# - The rules are checked on their own (suricata -T); the old files come back
#   if the check fails.
# - Then Suricata is restarted (a rule reload keeps the old lists), and the
#   dashboard's rule count and rule index are brought up to date.
#
# To take the rules out of Suricata again:
#
#     sudo deploy/install-tls-fingerprints.sh --remove
#
# That empties /etc/suricata/rules/tls-fingerprints.rules (an empty file
# loads no rules; the old one is kept as *.bak-<time>) and leaves
# tls-fingerprints.off beside it, so deploy/apply-suricata-settings.sh leaves
# them out too; running this without --remove puts them back. The TLS
# Fingerprints page doesn't need them: it reads Suricata's TLS records.
set -euo pipefail

restart=yes
mode=install
case "${1:-}" in
    "") ;;
    --no-restart) restart=no ;;
    --remove) mode=remove ;;
    -h | --help) sed -n '2,31p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $1 (see --help)" >&2; exit 2 ;;
esac

if [[ $EUID -ne 0 ]]; then
    echo "Run it with sudo: sudo $0" >&2
    exit 1
fi
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
owner="$(stat -c %U "$repo_dir")"
source_dir="$repo_dir/deploy/suricata/tls-fingerprints"
config=/etc/suricata/suricata.yaml
rules_dir=/etc/suricata/rules
logs=/var/log/suricata
stamp="$(date +%Y%m%d-%H%M%S)"
installed=(
    tls-fingerprints.rules
    tls-fingerprints.lua
    tls-fingerprints-bad-ja4.lst
    tls-fingerprints-bad-ja3.lst
    tls-fingerprints-bad-ja3s.lst
)
# Left by --remove: the rules stay out (deploy/apply-suricata-settings.sh).
off="$rules_dir/tls-fingerprints.off"

if [[ $mode == remove ]]; then
    echo "== Taking the TLS fingerprint rules out of Suricata"
    if [[ -s "$rules_dir/tls-fingerprints.rules" ]]; then
        cp -p "$rules_dir/tls-fingerprints.rules" "$rules_dir/tls-fingerprints.rules.bak-$stamp"
    fi
    install -m 0644 /dev/null "$rules_dir/tls-fingerprints.rules"
    printf '%s\n' "Left by deploy/install-tls-fingerprints.sh --remove on $(date '+%F %T'):" \
        "the TLS fingerprint rules stay out; running it without --remove puts them back." > "$off"
    echo "   $rules_dir/tls-fingerprints.rules is empty; $off left"
else

echo "== Checking the known-bad lists and writing them for Suricata"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
python3 - "$source_dir" "$work" <<'PYTHON'
import base64
import re
import sys
from pathlib import Path

source, out = Path(sys.argv[1]), Path(sys.argv[2])
shapes = {
    "ja4": re.compile(r"^[tqd][0-9a-z]{2}[di][0-9]{4}[0-9a-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$"),
    "ja3": re.compile(r"^[0-9a-f]{32}$"),
    "ja3s": re.compile(r"^[0-9a-f]{32}$"),
}
wrong = []
for kind, shape in shapes.items():
    listed = source / f"known-bad-{kind}.txt"
    values = []
    for number, line in enumerate(listed.read_text(encoding="utf-8").splitlines(), start=1):
        value = line.split("#", 1)[0].strip().lower()
        if not value:
            continue
        if not shape.match(value):
            wrong.append(f"{listed.name} line {number}: {value!r} isn't a {kind.upper()} fingerprint")
            continue
        if value not in values:
            values.append(value)
    # Suricata's string datasets hold one Base64 value per line.
    (out / f"tls-fingerprints-bad-{kind}.lst").write_text(
        "".join(base64.b64encode(value.encode()).decode() + "\n" for value in values)
    )
    print(f"   {kind.upper()}: {len(values)}")
if wrong:
    sys.exit("!! " + "\n!! ".join(wrong))
PYTHON
cp "$source_dir/tls-fingerprints.rules" "$source_dir/tls-fingerprints.lua" "$work/"

echo "== Checking the rules on their own (suricata -T)"
# The Lua script's place in the rules is where it is installed; the check
# reads the new script from the work folder instead.
sed "s#$rules_dir/tls-fingerprints.lua#$work/tls-fingerprints.lua#" \
    "$work/tls-fingerprints.rules" > "$work/check.rules"
mkdir -p "$work/log"
# Where Suricata keeps what it has seen; the check needs it too.
install -d -m 0755 /var/lib/suricata/data
if ! suricata -T -c "$config" -S "$work/check.rules" -l "$work/log" > "$work/test.log" 2>&1; then
    echo "!! Suricata doesn't accept them. Its output:" >&2
    tail -n 20 "$work/test.log" >&2
    exit 1
fi

echo "== Installing them in $rules_dir"
for file in "${installed[@]}"; do
    if [[ -e "$rules_dir/$file" ]]; then
        cp -p "$rules_dir/$file" "$rules_dir/$file.bak-$stamp"
    fi
    install -m 0644 "$work/$file" "$rules_dir/$file"
done

echo "== Adding them to Suricata's rule-files"
python3 - "$config" "$rules_dir/tls-fingerprints.rules" <<'PYTHON'
import re
import sys
from pathlib import Path

path, rules = Path(sys.argv[1]), sys.argv[2]
lines = path.read_text().splitlines(keepends=True)
start = next((i for i, line in enumerate(lines) if re.match(r"^rule-files:", line)), None)
if start is None:
    sys.exit(f"!! no rule-files: in {path}")
entries = []
for index in range(start + 1, len(lines)):
    match = re.match(r"^(\s+)-\s*(\S+)", lines[index])
    if match:
        entries.append((index, match.group(1), match.group(2)))
    elif lines[index].strip() and not lines[index].lstrip().startswith("#"):
        break
if any(entry == rules for _, _, entry in entries):
    print("   already there")
    sys.exit()
if not entries:
    sys.exit(f"!! rule-files: in {path} lists no file")
last, lead, _ = entries[-1]
lines.insert(last + 1, f"{lead}- {rules}\n")
path.write_text("".join(lines))
print(f"   added {rules}")
PYTHON
rm -f "$off"
fi

if [[ $restart == no ]]; then
    echo "== Installed; Suricata loads them when it restarts"
    exit 0
fi

echo "== Restarting Suricata"
loaded_before="$(grep -c 'rules successfully loaded' "$logs/suricata.log" 2>/dev/null || true)"
systemctl restart suricata
# Loading the rules takes a minute or so.
for _ in $(seq 1 60); do
    if [[ "$(grep -c 'rules successfully loaded' "$logs/suricata.log" 2>/dev/null || true)" -gt "${loaded_before:-0}" ]]; then
        break
    fi
    sleep 3
done
if ! systemctl is-active --quiet suricata; then
    echo "!! Suricata didn't start; the old files are kept as $rules_dir/*.bak-$stamp." >&2
    echo "!! journalctl -u suricata and $logs/suricata.log say why." >&2
    exit 1
fi
grep 'rules successfully loaded' "$logs/suricata.log" | tail -n 1
cd "$repo_dir"
runuser -u "$owner" -- .venv/bin/python scripts/save_rule_counts.py --suricata-log \
    || echo "!! The rule count wasn't saved; run scripts/save_rule_counts.py --suricata-log later." >&2
runuser -u "$owner" -- env PYTHONPATH=src .venv/bin/python src/ids/build_rule_index.py > /dev/null \
    || echo "!! The rule index wasn't rebuilt; run src/ids/build_rule_index.py later." >&2
systemctl try-restart ids-dashboard 2> /dev/null || true
echo "== Done"
