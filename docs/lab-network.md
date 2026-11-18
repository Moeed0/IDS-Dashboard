# Lab network: the mirroring switch and adding routers

The IDS is passive: it never sits in the path of the traffic and never
forwards or blocks anything. A managed switch sends it a **copy** of the
traffic on chosen ports (port mirroring). Snort and Suricata listen on the
VM's `ens34`, which is bridged to the IDS PC's Ethernet port.

## The pieces

| Device | Model | Role | Address |
| --- | --- | --- | --- |
| Main router | Linksys EA6300 | Gateway and DHCP for the lab, no internet | 192.168.50.1 |
| Switch | TP-Link TL-SG3210 v3 (8 × 1 Gbit + 2 SFP, L2+ managed) | Joins everything; mirrors chosen ports to port 8 | 192.168.50.2 (fixed) |
| Second router | TP-Link Archer C6 v6 | Wi-Fi and extra ports for the same lab network (access point) | 192.168.50.3 (fixed) |
| IDS PC | Windows host, Ubuntu VM | Listens on switch port 8 (`ens34`, 192.168.50.135) | from DHCP |

Fixed addresses must sit **outside the main router's DHCP range** (check it
in the Linksys page under Connectivity → Local Network). Keep the list above
up to date when something is added.

## Switch ports

| Port | Connected to | Mirrored |
| --- | --- | --- |
| 1 | Main router (a LAN port) | no |
| 2 | Laptop used for tests | yes, ingress and egress |
| 3 | Archer C6 (a yellow LAN port) | yes, ingress and egress |
| 4-7 | Free: more devices or routers | add when used |
| 8 | IDS PC | mirror **destination** |

Don't mirror port 1 as well: traffic between a mirrored port and port 1 would
then be copied twice, and the engines would raise each alert twice. Traffic
between two mirrored ports (laptop ↔ a Wi-Fi device) is copied twice for the
same reason.

## Setting up the switch (once)

1. Power it on with only a laptop connected (any port). Give the laptop the
   fixed address 192.168.0.10, mask 255.255.255.0, no gateway.
2. Open http://192.168.0.1 and log in with the default account printed on
   the switch's label. It asks for a new password: choose one and keep it.
3. Mirroring (L2 Features → Mirroring; Switching → Port Mirror on older
   firmware): session 1, **destination port 8**, **source ports 2 and 3**,
   mode **ingress and egress**.
4. System → IP settings: fixed address **192.168.50.2**, mask 255.255.255.0,
   gateway 192.168.50.1. The page stops answering at the old address.
5. **Save the configuration** (the Save icon at the top of the page). Without
   it the switch forgets everything at its next restart.
6. Set the laptop back to automatic (DHCP).

Later, the switch's page is at http://192.168.50.2 from any device in the lab.

## Adding a router (the Archer C6, and any later one)

A router added to the lab works as an **access point**: it gives Wi-Fi and
extra ports on the same 192.168.50.x network. The main router keeps handing
out every address, so the IDS sees each device's own address. These steps
work on any brand.

1. Set it up on its own: connect only the laptop to one of its LAN ports
   (on the Archer C6 the yellow ones), laptop on automatic (DHCP). Open its
   page (Archer C6: http://192.168.0.1 or http://tplinkwifi.net) and create
   its admin password. Skip any internet setup wizard.
2. Wi-Fi: set a name and password (Archer C6: Wireless).
3. **Turn its DHCP server off** (Archer C6: Advanced → Network → DHCP
   Server). Only the main router may hand out addresses.
4. Give it a fixed address in the lab, outside the DHCP range, not used by
   anything else: **192.168.50.3** for the Archer C6, then .4, .5, … for
   later routers (Archer C6: Advanced → Network → LAN). It restarts; to reach
   it again, give the laptop the fixed address 192.168.50.10 (mask
   255.255.255.0) and open http://192.168.50.3. Check the settings stuck,
   then set the laptop back to DHCP.
5. Cable it: one of its **LAN** ports to a free switch port. Leave its
   **WAN/Internet port (blue on the Archer C6) empty**.
6. On the switch, add that port to the mirroring source ports (ingress and
   egress) and save the configuration.
7. Add it to the tables above.

Check: a phone or laptop on the new Wi-Fi gets a 192.168.50.x address (from
the main router), can ping 192.168.50.1, and on the IDS VM

    sudo tcpdump -i ens34 -nn host <that device's address>

shows its traffic.

### What the IDS can't see behind a router

Traffic that stays inside the added router never reaches the switch: between
two devices on its Wi-Fi, or on its own LAN ports. Plug devices you test from
into the switch directly, or test between a device behind the router and one
on another switch port.

### A router with its own network (not used here)

A router connected by its **WAN** port, with its DHCP on, makes a separate
network behind it (for example 192.168.60.x) and hides its devices behind its
one 192.168.50.x address (NAT). The IDS then sees only that one address, so
this lab adds routers as access points as above.

## Checking the IDS sees mirrored traffic

1. On the VM, `ip -br addr show ens34` still shows 192.168.50.135, and the
   dashboard opens.
   - If not, port 8 is not passing normal traffic while it is the mirror
     destination. Then the IDS PC needs a second connection: a normal switch
     port into a second Ethernet port (or a USB Ethernet adapter) on the PC.
2. From the laptop on port 2, `ping 192.168.50.1`.
3. On the VM, `sudo tcpdump -i ens34 -nn icmp and not host 192.168.50.135`
   shows those pings: traffic that isn't the IDS's own.
