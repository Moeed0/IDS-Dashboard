#!/usr/bin/env bash
# Sets up the dashboard on this machine in one go, once Snort 3, Suricata 8
# or both are installed (README, "Setting up a machine"). Run it as your
# user; it asks for sudo for the steps that need it, and it can be run again
# at any time: it keeps .env and redoes the rest.
set -euo pipefail

usage() {
    cat <<'TEXT'
Usage: ./setup.sh [--no-system] [--no-local-rules] [--with-intel]

  1. a Python environment with the dashboard's packages (.venv);
  2. this machine's settings (.env, from .env.example, for the engines
     found here), unless there is one already;
  3. the page: kept when it is built already, as in a release zip, or built
     with Node.js;
  4. the rule index, which the combined export uses;
  5-7. with sudo: read access to the engines' logs; the basic local rules
     both engines share (deploy/rules/local.rules) put into them, with
     their rule counts for the Overview; and the collector and dashboard as
     services, which start now and at every boot.

  --no-system       steps 1-4 only, without sudo
  --no-local-rules  leave the local rules out of the engines (and empty
                    IDS_LOCAL_RULES in .env, so later runs leave them out too)
  --with-intel  also download the threat-intel sources (NVD, EPSS, CISA KEV,
                MITRE ATT&CK; about 300 MB) and build their 1.6 GB database,
                for the CVE and ATT&CK details in the combined export
TEXT
}

SYSTEM=yes
INTEL=no
LOCAL_RULES=yes
for option in "$@"; do
    case "$option" in
        --no-system) SYSTEM=no ;;
        --with-intel) INTEL=yes ;;
        --no-local-rules) LOCAL_RULES=no ;;
        -h | --help) usage; exit 0 ;;
        *) echo "Unknown option: $option" >&2; usage >&2; exit 2 ;;
    esac
done

if [ "$EUID" -eq 0 ]; then
    echo "Run it as your user, without sudo: it asks for sudo where needed." >&2
    exit 1
fi

cd "$(dirname "$0")"

echo "== 1. Python environment (.venv)"
PYTHON=python3
if command -v python3.13 > /dev/null; then
    PYTHON=python3.13
fi
if ! command -v "$PYTHON" > /dev/null; then
    echo "!! Python 3 isn't installed: sudo apt install python3 python3-venv" >&2
    exit 1
fi
VERSION="$("$PYTHON" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
if [ "$VERSION" != "3.13" ]; then
    echo "   Using Python $VERSION; the dashboard is tested with 3.13."
fi
if [ ! -e .venv ]; then
    if ! "$PYTHON" -m venv .venv; then
        rm -rf .venv
        echo "!! Python couldn't make .venv: sudo apt install python$VERSION-venv" >&2
        exit 1
    fi
fi
.venv/bin/pip install --quiet --disable-pip-version-check -r requirements.txt

echo "== 2. Settings (.env)"
if [ -f .env ]; then
    echo "   Keeping the .env that is here."
else
    ENGINES=()
    if command -v snort > /dev/null; then ENGINES+=(snort); fi
    if command -v suricata > /dev/null; then ENGINES+=(suricata); fi
    cp .env.example .env
    chmod 600 .env
    if [ ${#ENGINES[@]} -gt 0 ]; then
        sed -i "s/^IDS_ENGINES=.*/IDS_ENGINES=$(IFS=,; echo "${ENGINES[*]}")/" .env
        echo "   Made .env from .env.example, for ${ENGINES[*]}."
    else
        echo "   Made .env from .env.example. Neither snort nor suricata is on the PATH:"
        echo "   set IDS_ENGINES in .env to the engines this machine runs."
    fi
    echo "   Check that its paths (logs, rules, configs) are this machine's."
fi
if [ "$LOCAL_RULES" = no ]; then
    sed -i "s|^IDS_LOCAL_RULES=.*|IDS_LOCAL_RULES=|" .env
    grep -q "^IDS_LOCAL_RULES=" .env || echo "IDS_LOCAL_RULES=" >> .env
    echo "   IDS_LOCAL_RULES is empty: no local rules on this machine."
fi

echo "== 3. The page (web/dist)"
if [ -f web/dist/index.html ]; then
    echo "   Built already."
elif command -v npm > /dev/null; then
    (cd web && npm ci --no-audit --no-fund --loglevel=error && npm run build)
else
    echo "!! The page isn't built, and Node.js isn't here to build it. Use the release" >&2
    echo "   zip, which has it built (https://github.com/Moeed0/IDS-Dashboard/releases/latest)," >&2
    echo "   or install Node.js 22 (sudo apt install nodejs npm) and run ./setup.sh again." >&2
    exit 1
fi

echo "== 4. Rule index (data/lab/rules/ids_rules.db)"
index_log="$(mktemp)"
if ! PYTHONPATH=src .venv/bin/python src/ids/build_rule_index.py > "$index_log"; then
    cat "$index_log"
    rm -f "$index_log"
    echo "!! The rule index wasn't built." >&2
    exit 1
fi
# A missing rules folder, and the total.
grep -E "^(No |Total indexed)" "$index_log" || true
rm -f "$index_log"

if [ "$INTEL" = yes ]; then
    echo "== Threat-intel database (data/intel/intel.db)"
    .venv/bin/python scripts/download_intel_sources.py --build
fi

if [ "$SYSTEM" = no ]; then
    echo "== Done, without the steps that need sudo (--no-system)."
    exit 0
fi

# This machine's settings, as the collector and the dashboard read them.
setting() {
    PYTHONPATH=src .venv/bin/python -c "from ids.config import get_settings; print(get_settings().$1)"
}
RUN_ENGINES="$(PYTHONPATH=src .venv/bin/python -c 'from ids.config import get_settings; print(" ".join(get_settings().engines))')"

echo "== 5. Read access to the engines' logs (sudo)"
if ! command -v setfacl > /dev/null; then
    echo "!! setfacl isn't installed: sudo apt install acl, then run ./setup.sh again." >&2
    exit 1
fi
for engine in $RUN_ENGINES; do
    case "$engine" in
        snort) log="$(setting snort_alert_file)" ;;
        suricata) log="$(setting suricata_eve_file)" ;;
    esac
    folder="$(dirname "$log")"
    if sudo test -d "$folder"; then
        # The folder, its new files (after log rotation) and the log itself.
        sudo setfacl -m "u:$USER:rx" "$folder"
        sudo setfacl -d -m "u:$USER:r" "$folder"
        if sudo test -f "$log"; then
            sudo setfacl -m "u:$USER:r" "$log"
        fi
        echo "   $USER can read $log"
    else
        echo "!! $folder doesn't exist yet: start $engine, then run ./setup.sh again."
    fi
done

if [ -n "$(setting "local_rules or ''")" ]; then
    echo "== 6. Local rules, and the rule counts for the Overview"
    deploy/install-local-rules.sh
else
    echo "== 6. Rule counts for the Overview"
    COUNTS=()
    for engine in $RUN_ENGINES; do
        case "$engine" in
            snort)
                echo "   Asking Snort how many rules it loads (snort -T loads them all: about a minute)"
                config="$(setting snort_config)"
                count="$(sudo snort -c "$config" -T 2>&1 | grep -oP 'total rules loaded: \K\d+' || true)"
                if [ -n "$count" ]; then
                    COUNTS+=(--snort "$count")
                else
                    echo "!! Snort's config didn't load; see: sudo snort -c $config -T"
                fi
                ;;
            suricata) COUNTS+=(--suricata-log) ;;
        esac
    done
    if [ ${#COUNTS[@]} -gt 0 ] && ! .venv/bin/python scripts/save_rule_counts.py "${COUNTS[@]}"; then
        echo "!! Not saved: the Overview shows no rule counts until scripts/save_rule_counts.py runs."
    fi
fi

echo "== 7. The collector, the dashboard and the nightly backup as services (sudo)"
sudo deploy/install-services.sh > /dev/null
# Started now if they weren't running; started again if they were, so that
# they read this setup's settings and files.
sudo systemctl restart ids-collector ids-dashboard
systemctl is-active ids-collector ids-dashboard | paste -sd " " | sed 's/^/   ids-collector, ids-dashboard: /' || true

echo "== Done. Open http://<this machine's address>:8501/ (its addresses: $(hostname -I | xargs))"
if ! grep -qi "^IDS_API_REQUIRE_TOKEN=false" .env; then
    echo "   The page asks for the API token, which this shows: grep IDS_API_TOKEN .env"
fi
