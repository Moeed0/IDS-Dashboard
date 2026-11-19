# Lab network: the router, the mirroring switch and growing the lab

The IDS is passive: it never sits in the path of the traffic and never
forwards or blocks anything. A managed switch sends it a **copy** of the
traffic on chosen ports (port mirroring). Snort and Suricata listen on the
VM's `ens34`, which is bridged to the IDS PC's Ethernet port.

```
                 Archer C6 (main router, 192.168.50.1, DHCP, Wi-Fi)
                     │ yellow LAN port        (blue WAN port: empty)
                     ▼
   ┌──────────── TP-Link TL-SG3210 switch (192.168.50.2) ────────────┐
   │ port 1: Archer C6   port 2: laptop   ports 3-7: free            │
   │ port 8: IDS PC  ◄── a copy of every packet entering ports 1-7   │
   └─────────────────────────────────────────────────────────────────┘
```

## Devices and addresses

| Device | Model | Role | Address |
| --- | --- | --- | --- |
| Main router | TP-Link Archer C6 v6 | Gateway, DHCP and Wi-Fi for the lab; no internet | 192.168.50.1 |
| Switch | TP-Link TL-SG3210 v3 (8 × 1 Gbit + 2 SFP, L2+ managed) | Joins the lab; mirrors chosen ports to port 8 | 192.168.50.2 (fixed) |
| IDS PC | Windows host, Ubuntu VM | Listens on switch port 8 (`ens34`, MAC 00:0c:29:1e:da:cb) | VM 192.168.50.135 (reserved in the router); Windows host by DHCP (192.168.50.143 on 19 Nov 2026) |

Address plan, so that added devices never clash:

| Addresses | For |
| --- | --- |
| .1 | the main router |
| .2-.9 | switches (.2 the TL-SG3210, then .3, .4, …) |
| .10-.29 | added routers, as access points (.10, .11, …) |
| .30-.99 | other devices that need a fixed address |
| .100-.199 | handed out by the main router's DHCP (.135 reserved for the IDS) |

The IDS's test alert pings 192.168.50.1 (`IDS_TEST_ALERT_TARGET` in `.env`),
so the main router keeps that address. Keep these tables current when the
lab changes.

## Switch ports

| Port | Connected to | Mirrored |
| --- | --- | --- |
| 1 | Archer C6 (a yellow LAN port) | **yes**, ingress only |
| 2 | Laptop used for tests | **yes**, ingress only |
| 3-7 | free (for more devices, switches or routers) | **yes**, ingress only |
| 8 | IDS PC | mirror **destination** |

## 1. The Archer C6 (main router)

Set it up with only the laptop connected to it.

1. Power it on. Connect the laptop to a **yellow** LAN port; the laptop's
   network on automatic (DHCP). Leave the **blue WAN** port empty.
2. Open http://192.168.0.1 (or http://tplinkwifi.net). Create its admin
   password. If a quick-setup wizard asks about the internet connection,
   skip or exit it: the lab has no internet.
3. **Wireless**: set the Wi-Fi name and password.
4. **Advanced → Network → LAN**: IP address **192.168.50.1**, mask
   255.255.255.0. Save; the router restarts.
5. Unplug the laptop's cable and plug it back in: the laptop gets a
   192.168.50.x address. Open http://192.168.50.1 and log in.
6. **Advanced → Network → DHCP Server**: on, address pool
   **192.168.50.100 - 192.168.50.199**, gateway 192.168.50.1. Under
   **Address Reservation**, add MAC **00:0C:29:1E:DA:CB** → **192.168.50.135**
   (the IDS VM keeps its address). Save.

## 2. The TL-SG3210 switch

Set it up with only the laptop connected to it (not yet to the router: its
own first address, 192.168.0.1, is the Archer's old one).

1. Power it on. Connect the laptop to any port. Give the laptop the fixed
   address **192.168.0.10**, mask 255.255.255.0, no gateway.
2. Open http://192.168.0.1 and log in with the default account printed on
   the switch's label. It asks for a new password: choose one and keep it.
3. **Mirroring** (MAINTENANCE → Mirroring, the Port Mirroring Session
   List): **Edit** session 1. Destination Port Config: port **8**, Apply.
   Source Interfaces Config: tick **1/0/1 to 1/0/7**, **Ingress Enable**,
   **Egress Disable**, Apply. Back on the list: destination 1/0/8, sources
   1/0/1-7, mode Ingress. Then click **Save** at the top of the page.
4. **Its address** (L3 Features → Interface, VLAN 1; on older firmware
   System → System IP): fixed, **192.168.50.2**, mask 255.255.255.0,
   gateway 192.168.50.1. The page stops answering at the old address.
5. Set the laptop's fixed address to **192.168.50.10** for a moment, open
   http://192.168.50.2, log in and **Save the configuration** (the Save icon
   at the top of the page). Without this the switch forgets everything at
   its next restart.
6. Set the laptop back to automatic (DHCP).

## 3. Cabling

1. Archer C6 yellow LAN port → **switch port 1**.
2. Laptop → **switch port 2**.
3. IDS PC → **switch port 8** (its cable, moved from the old router).

## 4. Checks

1. On the VM: `ip -br addr show ens34` shows 192.168.50.135 (unplug and
   replug, or wait a minute, if it still shows an old address), and the
   dashboard opens.
   - If ens34 gets no address at all, port 8 is not passing normal traffic
     while it is the mirror destination. Then the IDS PC needs a second
     connection: a normal switch port into a second Ethernet port (or a USB
     Ethernet adapter) on the PC.
2. Laptop: gets a 192.168.50.1xx address; `ping 192.168.50.1` answers.
3. On the VM, while the laptop pings:

       sudo tcpdump -i ens34 -nn icmp and not host 192.168.50.135

   shows the laptop's pings to the router: traffic that isn't the IDS's own.
4. The dashboard's test alert (a ping to 192.168.50.1) still arrives.

## Choosing what to mirror

The TL-SG3210 copies the chosen source ports to **one** of its own ports (8).

- **Every port except 8, ingress only** (the setup above). Every packet
  enters the switch through exactly one port, so copying what *enters* each
  port gives the IDS every packet that crosses the switch **once**: the
  laptop's ping enters port 2, the router's reply enters port 1. This covers
  the router, every device and device-to-device traffic on the switch.
- Don't use **Both** (ingress and egress) on more than one port: a packet
  entering one mirrored port and leaving by another is copied twice, and
  the engines raise its alerts twice.
- The IDS PC's own traffic (the VM and the Windows host, port 8) still
  reaches the IDS normally. Replies to it enter a mirrored port, so they
  arrive twice: once delivered, once as the copy (`ping` from the VM shows
  "+1 duplicates"). Traffic between other devices is seen once.
- Traffic that stays inside the Archer C6 (between its Wi-Fi devices, or its
  own yellow ports) never reaches the switch. Plug test machines into the
  switch.
- The lab has no internet, so each DNS lookup a device makes is answered
  "Refused" by the Archer, and the router sends UPnP and IPv6 announcements
  on its own. With the whole switch mirrored these are seen too: on 19 Nov
  2026 that was about 2,500 alerts every 10 minutes with the laptop and the
  IDS PC connected, with no dropped packets.

## Growing the lab

### Another switch

1. Give it the next switch address (.3, .4, …) as in section 2; managed
   ones need it, unmanaged ones have none.
2. Connect one of its ports to a free port on the TL-SG3210, say port 7
   (the uplink).
3. Port 7 is already mirrored (ingress), so the IDS sees everything
   between that switch's devices and the rest of the lab. Traffic between
   two devices on the new switch never reaches the TL-SG3210, so the IDS
   doesn't see it; to see it, put those test machines on the TL-SG3210, or
   give the IDS a second capture port on the new switch (its own mirror
   destination). The same holds for every further switch chained behind it.
4. Add it to the tables above.

### Another router

An added router works as an **access point**: Wi-Fi and extra ports on the
same 192.168.50.x network, so the main router hands out every address and
the IDS sees each device's own address. On any brand:

1. Set it up with only the laptop connected to one of its LAN ports;
   create its admin password; skip the internet wizard.
2. Set its Wi-Fi name and password.
3. **Turn its DHCP server off.** Only the main router hands out addresses.
4. Give it the next access-point address (.10, .11, …) in its LAN
   settings. It restarts; to reach it again, give the laptop the fixed
   address 192.168.50.20 for a moment, check the settings stuck, then set
   the laptop back to DHCP.
5. Connect one of its **LAN** ports to a free switch port. Leave its
   **WAN/Internet** port empty.
6. Ports 1-7 are already mirrored (ingress), so its devices' traffic to
   the rest of the lab is seen.
7. Add it to the tables above.

Traffic between devices on the same added router stays inside it, as with
the Archer C6.

A router connected by its **WAN** port with its DHCP on would make a
separate network behind it (for example 192.168.60.x) and hide its devices
behind its one 192.168.50.x address (NAT): the IDS would see only that one
address. That's why routers are added as access points.
