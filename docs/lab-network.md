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
   │ port 1: Archer C6   port 2: laptop (mirrored)   ports 3-7: free │
   │ port 8: IDS PC  ◄── gets a copy of every packet on port 2       │
   └─────────────────────────────────────────────────────────────────┘
```

## Devices and addresses

| Device | Model | Role | Address |
| --- | --- | --- | --- |
| Main router | TP-Link Archer C6 v6 | Gateway, DHCP and Wi-Fi for the lab; no internet | 192.168.50.1 |
| Switch | TP-Link TL-SG3210 v3 (8 × 1 Gbit + 2 SFP, L2+ managed) | Joins the lab; mirrors chosen ports to port 8 | 192.168.50.2 (fixed) |
| IDS PC | Windows host, Ubuntu VM | Listens on switch port 8 (`ens34`, MAC 00:0c:29:1e:da:cb) | 192.168.50.135 (reserved in the router) |

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
| 1 | Archer C6 (a yellow LAN port) | no |
| 2 | Laptop used for tests | **yes**, ingress and egress |
| 3-7 | free | see "Choosing what to mirror" |
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
3. **Mirroring** (L2 Features → Mirroring; on older firmware Switching →
   Port Mirror): session 1, **destination port 8**, **source port 2**,
   **ingress and egress** both on.
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

- **Each packet should cross only one mirrored port.** A packet that enters
  one mirrored port and leaves by another is copied twice, and the engines
  raise its alerts twice. So don't mirror port 1 (the router) together with
  device ports.
- Mirroring the **laptop's port** shows everything the laptop sends and
  receives, once. A test machine you attack from or to goes on a mirrored
  port.
- Mirroring **only port 1** instead shows everything between any device and
  the router (and the internet, if the lab ever gets it), but not
  device-to-device traffic on the switch.
- Traffic that stays inside the Archer C6 (between its Wi-Fi devices, or its
  own yellow ports) never reaches the switch. Plug test machines into the
  switch.

## Growing the lab

### Another switch

1. Give it the next switch address (.3, .4, …) as in section 2; managed
   ones need it, unmanaged ones have none.
2. Connect one of its ports to a free port on the TL-SG3210, say port 7
   (the uplink).
3. To see its devices' traffic, mirror **port 7** on the TL-SG3210: that
   shows everything between that switch's devices and the rest of the lab.
   Traffic between two devices on the new switch never crosses port 7; to
   see it, put those test machines on the TL-SG3210, or give the IDS a
   second capture port on the new switch (its own mirror destination).
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
6. Mirror that switch port if its devices are to be watched (and mind the
   one-mirrored-port rule above). Save the switch's configuration.
7. Add it to the tables above.

Traffic between devices on the same added router stays inside it, as with
the Archer C6.

A router connected by its **WAN** port with its DHCP on would make a
separate network behind it (for example 192.168.60.x) and hide its devices
behind its one 192.168.50.x address (NAT): the IDS would see only that one
address. That's why routers are added as access points.
