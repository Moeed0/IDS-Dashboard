#!/usr/bin/env bash
# Puts deploy/rules/local.rules, the basic rules Snort and Suricata share,
# into the engines this machine runs (IDS_ENGINES in .env), or takes them
# out again. setup.sh runs it when IDS_LOCAL_RULES in .env is set.
#
#   deploy/install-local-rules.sh           put them in
#   deploy/install-local-rules.sh --remove  take them out
#
# Putting them in:
#   - Suricata: checks the rules on their own, installs them as
#     /etc/suricata/rules/local.rules, adds that file to its config's
#     rule-files when it isn't there, and reloads its rules (restarts it
#     after a config change);
#   - Snort: installs them as /usr/local/etc/snort/local.rules, makes its
#     config include that file when it doesn't, checks the config with
#     snort -T (putting the old files back if it fails) and restarts Snort;
#   - the dashboard: sets IDS_LOCAL_RULES in .env, saves both engines' rule
#     counts, rebuilds the rule index, and restarts the API to show them.
# Taking them out empties both files, leaves the configs as they are (an
# empty file loads no rules), and does the rest with IDS_LOCAL_RULES empty.
#
# Run it as your user from anywhere, after ./setup.sh (it needs .venv and
# .env); it asks for sudo where needed. Old files are kept as *.bak-<time>.
set -euo pipefail

MODE=install
case "${1:-}" in
    "") ;;
    --remove) MODE=remove ;;
    -h | --help) sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $1 (see --help)" >&2; exit 2 ;;
esac

if [ "$EUID" -eq 0 ]; then
    echo "Run it as your user, without sudo: it asks for sudo where needed." >&2
    exit 1
fi

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"
if [ ! -x .venv/bin/python ] || [ ! -f .env ]; then
    echo "!! Run ./setup.sh first: this needs its .venv and .env." >&2
    exit 1
fi

RULES="$PROJECT_DIR/deploy/rules/local.rules"
SURICATA_LOCAL=/etc/suricata/rules/local.rules
SNORT_LOCAL=/usr/local/etc/snort/local.rules
SURICATA_LOG=/var/log/suricata/suricata.log
STAMP="$(date +%Y%m%d-%H%M%S)"
# What each engine's local file gets: these rules, or nothing.
SOURCE="$RULES"
if [ "$MODE" = remove ]; then
    SOURCE=/dev/null
fi

setting() {
    PYTHONPATH=src .venv/bin/python -c "from ids.config import get_settings; print(get_settings().$1)"
}
ENGINES=" $(setting "engines" | tr -d "(),'") "

# Keeps a copy of a file that has something in it.
keep() {
    if sudo test -s "$1"; then
        sudo cp "$1" "$1.bak-$STAMP"
    fi
}

COUNTS=()

if [[ "$ENGINES" == *" suricata "* ]]; then
    config="$(setting suricata_config)"
    if [ "$MODE" = install ]; then
        echo "== Suricata: checking the local rules on their own"
        # Its own log folder, so the test's count (just these rules) doesn't
        # end up in suricata.log, where the rule count is read below.
        test_dir="$(mktemp -d)"
        if ! sudo suricata -T -c "$config" -S "$RULES" -l "$test_dir" > "$test_dir/test.log" 2>&1; then
            echo "!! Suricata doesn't accept them. Full output: $test_dir/test.log" >&2
            exit 1
        fi
    fi

    echo "== Suricata: $SURICATA_LOCAL"
    keep "$SURICATA_LOCAL"
    sudo install -D -m 0644 "$SOURCE" "$SURICATA_LOCAL"
    loaded_before="$(sudo grep -c "rules successfully loaded" "$SURICATA_LOG" 2> /dev/null || true)"
    if [ "$MODE" = install ] && ! sudo grep -q "$SURICATA_LOCAL" "$config"; then
        echo "   Adding it to rule-files in $config"
        keep "$config"
        sudo sed -i "/^rule-files:/a\\  - $SURICATA_LOCAL" "$config"
        echo "   Restarting Suricata, which reads its config only when it starts"
        sudo systemctl restart suricata
    # The reload builds the new rules beside the old ones, so it takes a
    # minute and some memory, but Suricata captures all along.
    elif ! sudo suricatasc -c reload-rules > /dev/null 2>&1; then
        echo "   Restarting Suricata (its command socket isn't on)"
        sudo systemctl restart suricata
    fi

    # Its log says how many rules it loaded once it has: wait up to 3 min.
    for _ in $(seq 60); do
        if [ "$(sudo grep -c "rules successfully loaded" "$SURICATA_LOG" 2> /dev/null || true)" != "$loaded_before" ]; then
            COUNTS+=(--suricata-log)
            break
        fi
        sleep 3
    done
fi

if [[ "$ENGINES" == *" snort "* ]]; then
    config="$(setting snort_config)"
    echo "== Snort: $SNORT_LOCAL"
    keep "$SNORT_LOCAL"
    sudo install -D -m 0644 "$SOURCE" "$SNORT_LOCAL"
    changed=no
    if [ "$MODE" = install ] && ! sudo grep -q "$SNORT_LOCAL" "$config"; then
        echo "   Making $config include it"
        keep "$config"
        changed=yes
        printf '\n-- The local rules Snort and Suricata share (deploy/install-local-rules.sh).\nips = ips or {}\nips.rules = (ips.rules or "") .. "\\ninclude %s\\n"\n' "$SNORT_LOCAL" \
            | sudo tee -a "$config" > /dev/null
    fi

    echo "== Snort: checking its config (this loads all its rules)"
    if ! sudo snort -c "$config" -T > /tmp/snort-local-rules-test.log 2>&1 \
        || ! grep -q "successfully validated" /tmp/snort-local-rules-test.log; then
        echo "!! Snort's config doesn't load; putting the old files back." >&2
        echo "   Full output: /tmp/snort-local-rules-test.log" >&2
        if [ "$changed" = yes ]; then
            sudo cp "$config.bak-$STAMP" "$config"
        fi
        if sudo test -f "$SNORT_LOCAL.bak-$STAMP"; then
            sudo cp "$SNORT_LOCAL.bak-$STAMP" "$SNORT_LOCAL"
        else
            sudo install -m 0644 /dev/null "$SNORT_LOCAL"
        fi
        exit 1
    fi
    count="$(grep -oP 'total rules loaded: \K\d+' /tmp/snort-local-rules-test.log)"
    echo "   It loads $count rules."
    COUNTS+=(--snort "$count")

    service="$(systemctl list-units --type=service --all --no-legend 'snort*' | awk '{print $1}' | head -n 1)"
    if [ -n "$service" ]; then
        echo "== Snort: restarting $service"
        sudo systemctl restart "$service"
    else
        echo "!! No Snort service found here: restart Snort yourself to load them."
    fi
fi

echo "== Dashboard: IDS_LOCAL_RULES in .env"
value=""
if [ "$MODE" = install ]; then
    value=deploy/rules/local.rules
fi
if grep -q "^IDS_LOCAL_RULES=" .env; then
    sed -i "s|^IDS_LOCAL_RULES=.*|IDS_LOCAL_RULES=$value|" .env
else
    echo "IDS_LOCAL_RULES=$value" >> .env
fi
echo "   IDS_LOCAL_RULES=$value"

echo "== Dashboard: rule counts and rule index"
if [ ${#COUNTS[@]} -gt 0 ]; then
    .venv/bin/python scripts/save_rule_counts.py "${COUNTS[@]}" \
        || echo "!! The counts weren't saved; run scripts/save_rule_counts.py later."
fi
PYTHONPATH=src .venv/bin/python src/ids/build_rule_index.py > /dev/null
if systemctl list-unit-files ids-dashboard.service > /dev/null 2>&1; then
    sudo systemctl restart ids-dashboard
fi

if [ "$MODE" = install ]; then
    echo "== Done. Try it: ping a machine on the watched network; the Alert Explorer's"
    echo "   search for LOCAL then shows an alert from each engine."
else
    echo "== Done. The engines load no local rules now."
fi
