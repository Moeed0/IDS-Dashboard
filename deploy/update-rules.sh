#!/usr/bin/env bash
# Fetches each engine's newest rules and loads them. ids-rule-update.timer
# runs it every night (deploy/install-rule-updates.sh installs it); by hand:
#
#     sudo deploy/update-rules.sh              # Snort only when a week is up
#     sudo deploy/update-rules.sh --snort-now  # Snort now too
#
# - Suricata: suricata-update (ET Open, as /etc/suricata/enable.conf,
#   disable.conf and modify.conf say), then a rule reload, so capture
#   doesn't stop. --no-test: with HOME_NET "any" its test fails, and it
#   would put the old rules back.
# - Snort: Talos's registered rules, with the oinkcode in /etc/ids/oinkcode
#   (root only), once a week, their compiled SO rules copied to
#   /usr/local/lib/snort/so_rules; and Talos's free OpenAppID detectors in
#   /usr/local/lib/openappid, when snort.org has newer ones (or now, when
#   they're missing). They're checked with snort -T before Snort is
#   restarted with them; when the check fails the old ones come back.
# - Then the dashboard's rule counts and rule index, and a dashboard restart.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run it with sudo: sudo $0" >&2
    exit 1
fi
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
owner="$(stat -c %U "$repo_dir")"
# One setting from .env (only the one named: the file holds the API token).
setting() { grep -E "^$1=" "$repo_dir/.env" 2>/dev/null | tail -n 1 | cut -d= -f2- || true; }

engines="$(setting IDS_ENGINES)"
engines="${engines:-snort,suricata}"
snort_config="$(setting IDS_SNORT_CONFIG)"
snort_config="${snort_config:-/usr/local/etc/snort/snort.lua}"
snort_rules="$(setting IDS_SNORT_RULES)"
# The registered snapshot for Snort 3.12.
snapshot="${SNORT_SNAPSHOT:-31200}"
oinkcode_file=/etc/ids/oinkcode
fetched=/var/lib/ids/snort-rules-fetched
# Where Snort finds the compiled SO rules (--plugin-path) and the OpenAppID
# detectors (deploy/snort/snort.lua's app_detector_dir); root's, not the
# owner's, as Snort runs them as root. so_build: the snapshot's build of them.
so_rules=/usr/local/lib/snort/so_rules
so_build=ubuntu-x64
detectors=/usr/local/lib/openappid
counts=()
failed=0

# Talos's free OpenAppID detectors (no oinkcode): the newest on snort.org's
# downloads page, into $detectors.new when they aren't the ones in use.
# (Called after ||, where set -e is off, so each step is checked.)
fetch_detectors() {
    local id sum file
    id="$(curl -fsSL --retry 2 https://www.snort.org/downloads \
        | grep -oP 'href="/downloads/openappid/\K\d+' | head -n 1)" || true
    sum="$(curl -fsSL --retry 2 https://www.snort.org/downloads/openappid/md5s \
        | awk '$2 == "snort-openappid.tar.gz" { print $1 }')" || true
    if [[ -z $id || -z $sum ]]; then
        echo "!! The OpenAppID download wasn't found on snort.org: Snort keeps the detectors it has" >&2
        return 1
    fi
    if [[ -d $detectors/odp && "$(cat "$detectors/md5" 2>/dev/null)" == "$sum" ]]; then
        echo "== Snort: the OpenAppID detectors are the newest" \
             "(version $(grep -oP 'VERSION=\K\d+' "$detectors/odp/version.conf" 2>/dev/null))"
        return 0
    fi
    echo "== Snort: fetching the OpenAppID detectors"
    file="$(mktemp)"
    if ! curl -fsSL --retry 2 -o "$file" "https://www.snort.org/downloads/openappid/$id" \
        || [[ "$(md5sum < "$file" | cut -d' ' -f1)" != "$sum" ]]; then
        rm -f "$file"
        echo "!! The OpenAppID download failed or doesn't match its checksum" >&2
        return 1
    fi
    mkdir -p "$detectors.new"
    if ! tar -xzf "$file" -C "$detectors.new" --no-same-owner --no-same-permissions \
        || [[ ! -f $detectors.new/odp/version.conf ]]; then
        rm -rf "$file" "$detectors.new"
        echo "!! The OpenAppID download isn't the detectors: Snort keeps the ones it has" >&2
        return 1
    fi
    rm -f "$file"
    echo "$sum" > "$detectors.new/md5"
}

if [[ ",$engines," == *",suricata,"* ]]; then
    echo "== Suricata: suricata-update"
    # The repo's lists of rules to turn on, off and change are the ones used.
    install -m 0644 "$repo_dir"/deploy/suricata/{enable,disable,modify}.conf /etc/suricata/
    if suricata-update --no-test --quiet; then
        if systemctl is-active --quiet suricata; then
            # Waits until the new rules are in use, so the count below is theirs.
            suricatasc -c reload-rules > /dev/null && echo "   Reloaded: Suricata kept capturing"
            counts+=(--suricata-log)
        fi
    else
        echo "!! suricata-update failed: Suricata keeps the rules it had" >&2
        failed=1
    fi
fi

if [[ ",$engines," == *",snort,"* && -n "$snort_rules" ]]; then
    # The unpacked snapshot: rules/, etc/, so_rules/ and builtins/.
    rules_root="$(dirname "$snort_rules")"
    # Each folder is replaced whole: X.new goes in, and the one it replaces
    # is kept as X.previous (until the next run), or put back if Snort
    # doesn't accept the new one.
    for path in "$rules_root" "$so_rules" "$detectors"; do
        rm -rf "$path.new" "$path.previous"
    done
    weekly=yes
    if [[ "${1:-}" != "--snort-now" && -n "$(find "$fetched" -mtime -6 -print -quit 2>/dev/null)" ]]; then
        weekly=
        echo "== Snort: rules fetched $(date -r "$fetched" '+%-d %b'); the next fetch is a week after"
    fi

    if [[ $weekly && ! -s $oinkcode_file ]]; then
        echo "== Snort: no oinkcode in $oinkcode_file, so its rules aren't fetched"
        echo "   (sudo deploy/install-rule-updates.sh asks for it)"
    elif [[ $weekly ]]; then
        echo "== Snort: fetching the registered rules (snapshot $snapshot)"
        download="$(mktemp)"
        trap 'rm -f "$download"' EXIT
        # The oinkcode reaches curl in a config file, never on a command line.
        # -L: snort.org answers with a redirect to the file.
        if curl -fsSL --retry 2 -o "$download" --config <(
            printf 'url = "https://www.snort.org/rules/snortrules-snapshot-%s.tar.gz?oinkcode=%s"\n' \
                "$snapshot" "$(< "$oinkcode_file")"
        ); then
            mkdir "$rules_root.new"
            if ! tar -xzf "$download" -C "$rules_root.new" || [[ ! -d "$rules_root.new/rules" ]]; then
                rm -rf "$rules_root.new"
                echo "!! The download isn't a rules archive: Snort keeps the rules it had" >&2
                failed=1
            fi
        else
            echo "!! The download failed: a wrong or expired oinkcode" \
                 "(sudo deploy/install-rule-updates.sh --new-oinkcode), or Talos's" \
                 "limit on how often a snapshot may be fetched" >&2
            failed=1
        fi
    fi

    # The OpenAppID detectors: once a week too, or now when they're missing.
    if [[ $weekly || ! -d $detectors/odp ]]; then
        fetch_detectors || failed=1
    fi

    # The compiled SO rules, copied out of the owner's folder because Snort
    # runs them as root: from the new rules, or from the ones in use when
    # they aren't there yet.
    so_from=
    if [[ -d $rules_root.new ]]; then
        so_from="$rules_root.new"
    elif [[ ! -d $so_rules ]]; then
        so_from="$rules_root"
    fi
    if [[ $so_from ]]; then
        if compgen -G "$so_from/so_rules/precompiled/$so_build/*.so" > /dev/null; then
            install -d -m 0755 "$so_rules.new"
            install -m 0644 "$so_from"/so_rules/precompiled/"$so_build"/*.so "$so_rules.new"/
        else
            echo "!! No compiled SO rules in $so_from/so_rules/precompiled/$so_build" >&2
            failed=1
        fi
    fi

    swapped=()
    for path in "$rules_root" "$so_rules" "$detectors"; do
        if [[ -d $path.new ]]; then
            if [[ -e $path ]]; then
                mv "$path" "$path.previous"
            fi
            mv "$path.new" "$path"
            swapped+=("$path")
        fi
    done
    if (( ${#swapped[@]} )); then
        if [[ -d $rules_root.previous ]]; then
            chown -R "$owner:" "$rules_root"
        fi
        echo "== Snort: checking its config with ${swapped[*]} (this loads all its rules)"
        test_log="$(mktemp)"
        if snort -c "$snort_config" --plugin-path "$so_rules" -T > "$test_log" 2>&1 \
            && grep -q "Snort successfully validated the configuration" "$test_log"; then
            loaded="$(grep -oP 'total rules loaded: \K\d+' "$test_log")"
            counts+=(--snort "$loaded")
            systemctl restart snort-lab
            if [[ -d $rules_root.previous ]]; then
                install -d /var/lib/ids
                touch "$fetched"
            fi
            echo "   $loaded rules; Snort restarted with them"
        else
            install -d /var/lib/ids
            cp "$test_log" /var/lib/ids/snort-test.log
            for path in "${swapped[@]}"; do
                rm -rf "$path.failed"
                mv "$path" "$path.failed"
                if [[ -e $path.previous ]]; then
                    mv "$path.previous" "$path"
                fi
            done
            echo "!! Snort didn't accept them: the old ones are back (the new ones:" \
                 "the .failed folders; the check's output: /var/lib/ids/snort-test.log)" >&2
            failed=1
        fi
        rm -f "$test_log"
    fi
fi

echo "== Dashboard: rule counts and rule index"
cd "$repo_dir"
if (( ${#counts[@]} )); then
    runuser -u "$owner" -- .venv/bin/python scripts/save_rule_counts.py "${counts[@]}" \
        || echo "!! The counts weren't saved; run scripts/save_rule_counts.py later." >&2
fi
runuser -u "$owner" -- env PYTHONPATH=src .venv/bin/python src/ids/build_rule_index.py > /dev/null \
    || echo "!! The rule index wasn't rebuilt; run src/ids/build_rule_index.py later." >&2
# It reads the counts when it starts.
systemctl try-restart ids-dashboard
exit "$failed"
