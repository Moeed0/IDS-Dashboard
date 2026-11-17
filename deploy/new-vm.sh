#!/usr/bin/env bash
# Sets up a fresh Ubuntu VM as this lab, from nothing to both engines
# writing alerts and the dashboard running, in one go:
#
#     sudo deploy/new-vm.sh --interface ens34
#
# --interface: the card on the network to watch (ip -br link). It asks once,
# at the start, for Snort's oinkcode (deploy/install-rule-updates.sh), then:
#
#  1. the packages: Suricata 8 (Ubuntu's), git, acl, Node.js, Python's venv,
#     ethtool, and what Snort 3 is built with;
#  2. Snort 3 from source (libdaq, then Snort; Ubuntu has no Snort 3), in
#     /usr/local, unless that version is there already (about 15 minutes);
#  3. the dashboard's own steps as the folder's owner (./setup.sh
#     --no-system: .venv, .env, the page, the rule index), with
#     IDS_INTERFACE and the hourly test alert's target (the card's
#     gateway) set in .env;
#  4. the capture card's name kept and its offloads off
#     (deploy/pin-capture-interface.sh);
#  5. the rules: ET Open for Suricata, the registered rules, their SO rules
#     and the OpenAppID detectors for Snort (deploy/update-rules.sh), and the
#     nightly update timer;
#  6. this lab's Snort config and service (deploy/apply-snort-config.sh) and
#     Suricata settings (deploy/apply-suricata-settings.sh), both capturing
#     on the card, both with every rule on;
#  7. ./setup.sh --with-intel as the owner: the threat-intel database (about
#     300 MB to download), log access, the local rules and the services. It
#     asks for the owner's sudo password again if the last one has expired.
#
# It can be run again: the build is skipped when it is done, .env is kept
# (its IDS_INTERFACE set again), and each script it runs can run again.
set -euo pipefail

SNORT_VERSION=3.12.4.0
DAQ_VERSION=3.0.28

usage() { sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; }

iface=
while [[ $# -gt 0 ]]; do
    case "$1" in
        --interface) iface="${2:-}"; shift 2 ;;
        --interface=*) iface="${1#*=}"; shift ;;
        -h | --help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "Run it with sudo: sudo $0 --interface <card>" >&2
    exit 1
fi
if [[ -z $iface ]]; then
    echo "Name the card to watch: --interface <card> (ip -br link shows them)" >&2
    exit 2
fi
if [[ ! -e /sys/class/net/$iface ]]; then
    echo "!! There's no interface $iface (ip -br link shows them)" >&2
    exit 1
fi
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
owner="$(stat -c %U "$repo_dir")"
if [[ $owner == root ]]; then
    echo "!! $repo_dir belongs to root: clone it as your user" >&2
    exit 1
fi
as_owner() { runuser -u "$owner" -- "$@"; }
cd "$repo_dir"

echo "== Snort's oinkcode, for its registered rules"
deploy/install-rule-updates.sh
if [[ ! -s /etc/ids/oinkcode ]]; then
    echo "!! No oinkcode: Snort's registered rules can't be fetched. Run it again with one." >&2
    exit 1
fi

echo "== 1. Packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
    suricata git acl ethtool curl nodejs npm python3-venv \
    build-essential cmake pkg-config autoconf automake libtool flex bison \
    libdumbnet-dev libhwloc-dev libluajit-5.1-dev libpcap-dev libpcre2-dev \
    libssl-dev zlib1g-dev liblzma-dev uuid-dev libunwind-dev libhyperscan-dev \
    libjemalloc-dev libmnl-dev libnetfilter-queue-dev libsafec-dev \
    libflatbuffers-dev libgoogle-perftools-dev > /dev/null
# Suricata starts at install on Ubuntu's default card; it's set up below.
systemctl stop suricata 2> /dev/null || true

echo "== 2. Snort $SNORT_VERSION"
if /usr/local/bin/snort -V 2>&1 | grep -q "Version ${SNORT_VERSION%.0}"; then
    echo "   Built already: $(/usr/local/bin/snort -V 2>&1 | grep -oP 'Version \S+')"
else
    build=/usr/local/src/ids-build
    rm -rf "$build"
    mkdir -p "$build"
    echo "   libdaq $DAQ_VERSION"
    curl -fsSL "https://github.com/snort3/libdaq/archive/refs/tags/v$DAQ_VERSION.tar.gz" \
        | tar -xz -C "$build"
    (
        cd "$build/libdaq-$DAQ_VERSION"
        ./bootstrap > "$build/daq.log" 2>&1
        ./configure --prefix=/usr/local >> "$build/daq.log" 2>&1
        make -j"$(nproc)" >> "$build/daq.log" 2>&1
        make install >> "$build/daq.log" 2>&1
    ) || { echo "!! libdaq didn't build: $build/daq.log" >&2; exit 1; }
    ldconfig
    echo "   Snort (about 15 minutes)"
    curl -fsSL "https://github.com/snort3/snort3/archive/refs/tags/$SNORT_VERSION.tar.gz" \
        | tar -xz -C "$build"
    (
        cd "$build/snort3-$SNORT_VERSION"
        ./configure_cmake.sh --prefix=/usr/local --enable-tcmalloc > "$build/snort.log" 2>&1
        cd build
        make -j"$(nproc)" >> "$build/snort.log" 2>&1
        make install >> "$build/snort.log" 2>&1
    ) || { echo "!! Snort didn't build: $build/snort.log" >&2; exit 1; }
    ldconfig
    /usr/local/bin/snort -V 2>&1 | grep -oP 'Version \S+.*' | sed 's/^/   /'
fi
install -d /var/log/snort

echo "== 3. The dashboard's files (as $owner)"
as_owner ./setup.sh --no-system
gateway="$(ip -4 route show default dev "$iface" | awk '{ print $3; exit }')"
as_owner sed -i "s|^IDS_INTERFACE=.*|IDS_INTERFACE=$iface|" .env
if [[ -n $gateway ]] && grep -q "^IDS_TEST_ALERT_TARGET=$" .env; then
    as_owner sed -i "s|^IDS_TEST_ALERT_TARGET=$|IDS_TEST_ALERT_TARGET=$gateway|" .env
fi
grep -E "^IDS_(INTERFACE|ENGINES|TEST_ALERT_TARGET)=" .env | sed 's/^/   /'

echo "== 4. The capture card $iface: its name kept, offloads off"
deploy/pin-capture-interface.sh | grep -v "change the card" || true
for offload in gro lro tso gso rx tx; do
    ethtool -K "$iface" "$offload" off 2> /dev/null || true
done

echo "== 5. Rules"
# The update checks the new Snort rules with the config in use (here still
# Snort's stock snort.lua) and restarts snort-lab, so the service is put in
# first; step 6 puts the lab's config in, which loads them all.
sed "s/-i ens38 /-i $iface /" deploy/systemd/snort-lab.service > /etc/systemd/system/snort-lab.service
install -d /etc/systemd/system/snort-lab.service.d
sed "s/-i ens38 /-i $iface /" deploy/systemd/snort-lab.service.d/daq-afpacket.conf \
    > /etc/systemd/system/snort-lab.service.d/daq-afpacket.conf
systemctl daemon-reload
deploy/update-rules.sh --snort-now || echo "!! Some rules weren't updated (see above)"
if [[ ! -d /usr/local/lib/snort/so_rules ]]; then
    echo "!! Snort's registered rules didn't arrive (see above). An HTTP 422 from snort.org" >&2
    echo "   means it refused the oinkcode: enter it again from your snort.org account page," >&2
    echo "   sudo deploy/install-rule-updates.sh --new-oinkcode, then run this again" >&2
    echo "   (the steps done already are quick the second time)." >&2
    exit 1
fi

echo "== 6. Snort's and Suricata's settings"
deploy/apply-snort-config.sh
deploy/apply-suricata-settings.sh
systemctl enable --quiet suricata

echo "== 7. ./setup.sh --with-intel (as $owner)"
as_owner ./setup.sh --with-intel

echo "== Done. Snort: $(systemctl is-active snort-lab), Suricata: $(systemctl is-active suricata)"
echo "   Alerts: /var/log/snort/alert_json.txt and /var/log/suricata/eve.json"
echo "   VMware must let the VM see others' traffic on $iface's network:"
echo "   promiscuous mode allowed on that virtual network (Windows host: on by default)."
