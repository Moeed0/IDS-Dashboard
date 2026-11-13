#!/usr/bin/env bash
# Run before VMware's adapter type of the capture card is changed (pcnet32 to
# vmxnet3): keeps the card's name (IDS_INTERFACE in .env, ens38) and its
# offloads off, whatever card VMware gives it.
#
#     sudo deploy/pin-capture-interface.sh
#
# Snort's service, Suricata's af-packet, NetworkManager and .env all find the
# card by its name, and a new adapter type comes up under a new one (its PCI
# slot changes). So a systemd .link file names it by its MAC address, which
# VMware keeps when only the adapter type changes. The same file turns
# offloads off from the moment the card appears: a card that merges packets
# (GRO, LRO) or leaves checksums to the hardware shows the engines packets
# the wire never carried. (Suricata turns them off when it starts too, but
# Snort may be reading first.)
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run it with sudo: sudo $0" >&2
    exit 1
fi
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
iface="$(grep -E '^IDS_INTERFACE=' "$repo_dir/.env" 2>/dev/null | tail -n 1 | cut -d= -f2- || true)"
iface="${iface:-ens38}"
if [[ ! -e /sys/class/net/$iface ]]; then
    echo "!! There's no interface $iface (IDS_INTERFACE in .env)" >&2
    exit 1
fi
mac="$(< "/sys/class/net/$iface/address")"
link=/etc/systemd/network/10-ids-capture.link

echo "== $link: the card with MAC $mac is always $iface"
install -d /etc/systemd/network
cat > "$link" <<EOF
# The IDS capture card (deploy/pin-capture-interface.sh): its name, whatever
# adapter type VMware gives it, and no offloads, so Snort and Suricata see
# the packets as they were on the wire.
[Match]
MACAddress=$mac

[Link]
Name=$iface
GenericReceiveOffload=false
LargeReceiveOffload=false
TCPSegmentationOffload=false
TCP6SegmentationOffload=false
GenericSegmentationOffload=false
ReceiveChecksumOffload=false
TransmitChecksumOffload=false
EOF
chmod 0644 "$link"

echo "== Early boot names cards too: rebuilding the initramfs with the file"
update-initramfs -u > /dev/null

echo "== Checking that the file is the one used for $iface"
# Kept whole first: grep -q stops reading early, which pipefail counts as a
# failure. Netplan's own .link files (in /run) may match the card too; the
# first by name wins.
check="$(udevadm test-builtin net_setup_link "/sys/class/net/$iface" 2>&1 || true)"
picked="$(grep -oP '^ID_NET_LINK_FILE=\K.*' <<< "$check" | tail -n 1)"
name="$(grep -oP '^ID_NET_NAME=\K.*' <<< "$check" | tail -n 1)"
if [[ $picked == "$link" && $name == "$iface" ]]; then
    echo "   Yes: udev names it $name with $picked."
    echo "   Now shut the VM down and change the card's type in VMware."
else
    echo "!! udev picks ${picked:-no file} (name ${name:-none}) for $iface:" \
         "don't change the card yet" >&2
    exit 1
fi
