# Lab network: the router, the mirroring switch and growing the lab

The IDS is passive: it never sits in the path of the traffic and never
forwards or blocks anything. A managed switch sends it a **copy** of the
traffic on chosen ports (port mirroring). Snort and Suricata listen on the
VM's `ens34`, which is bridged to the IDS PC's Ethernet port.

```
          Room router (internet; its own network 192.168.10.0/24)
                     │ a LAN port
                     ▼ blue WAN port (Dynamic IP: gets a 192.168.10.x address)
                 Archer C6 (main router, 192.168.50.1, DHCP; Wi-Fi off)
                     │ yellow LAN port
                     ▼
   ┌──────────── TP-Link TL-SG3210 switch (192.168.50.2) ────────────┐
   │ port 1: Archer C6   port 2: Linksys EA6300 (access point)       │
   │ ports 3-7: free (laptop for tests)                              │
   │ port 8: IDS PC  ◄── a copy of every packet entering ports 1-7   │
   └─────────────────────────────────────────────────────────────────┘
```

Since 25 Nov 2026 the lab has internet: the room's router feeds the
Archer's WAN port. The lab stays its own network (192.168.50.x) behind the
Archer, so the room router's network is never mirrored and its devices
never appear in the IDS.

## Devices and addresses

| Device | Model | Role | Address |
| --- | --- | --- | --- |
| Room router | (the room's own) | Internet for the lab, through the Archer's WAN port; not part of the lab | LAN 192.168.10.0/24; gives the Archer a 192.168.10.x address |
| Main router | TP-Link Archer C6 v6 | Gateway and DHCP for the lab; its Wi-Fi is off | 192.168.50.1 (LAN); WAN by DHCP from the room router |
| Switch | TP-Link TL-SG3210 v3 (8 × 1 Gbit + 2 SFP, L2+ managed) | Joins the lab; mirrors chosen ports to port 8 | 192.168.50.2 (fixed) |
| Access point | Linksys EA6300 | The lab's Wi-Fi: phones and laptops connect here, in Bridge Mode | 192.168.50.11 (fixed) |
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

The room router's network must never be 192.168.50.x: the Archer can't have
the same network on its WAN and LAN sides. If the room router changes, check
the address and mask a laptop gets from it (192.168.10.x with
255.255.255.0 on 25 Nov 2026); if it overlaps, change the room router's
LAN, not the lab.

## Switch ports

| Port | Connected to | Mirrored |
| --- | --- | --- |
| 1 | Archer C6 (a yellow LAN port) | **yes**, ingress only |
| 2 | Linksys EA6300, its yellow Internet port (Bridge Mode) | **yes**, ingress only |
| 3-7 | free: the laptop for tests, more switches or routers | **yes**, ingress only |
| 8 | IDS PC | mirror **destination** |

All of ports 1-7 are mirrored the same way, so a device works the same on
any of them; only port 8 is special.

## 1. The Archer C6 (main router)

Set it up with only the laptop connected to it.

1. Power it on. Connect the laptop to a **yellow** LAN port; the laptop's
   network on automatic (DHCP).
2. Open http://192.168.0.1 (or http://tplinkwifi.net). Create its admin
   password. If a quick-setup wizard asks about the internet connection,
   skip or exit it; step 7 sets it.
3. **Wireless**: turn the Wi-Fi **off**. People use the access point
   instead: traffic between devices on the Archer's own Wi-Fi never reaches
   the switch, so the IDS couldn't see it.
4. **Advanced → Network → LAN**: IP address **192.168.50.1**, mask
   255.255.255.0. Save; the router restarts.
5. Unplug the laptop's cable and plug it back in: the laptop gets a
   192.168.50.x address. Open http://192.168.50.1 and log in.
6. **Advanced → Network → DHCP Server**: on, address pool
   **192.168.50.100 - 192.168.50.199**, gateway 192.168.50.1. Under
   **Address Reservation**, add MAC **00:0C:29:1E:DA:CB** → **192.168.50.135**
   (the IDS VM keeps its address). Save.
7. **Advanced → Network → Internet**: Internet Connection Type **Dynamic
   IP**, MAC address **Use Default MAC Address**. Save. Then connect a LAN
   port of the room router to the Archer's **blue WAN** port; the status
   page shows the Internet connected with a 192.168.10.x address. Leave
   **Operation Mode** on Router.

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

1. Room router, a LAN port → Archer C6 **blue WAN** port.
2. Archer C6 yellow LAN port → **switch port 1**.
3. Linksys EA6300 **yellow Internet** port → **switch port 2** (set up as
   in "The Linksys EA6300 access point" below first).
4. Laptop for tests → any free port, 3-7.
5. IDS PC → **switch port 8**.

When the lab moves, unplug and replug in that order and power up the same
way: room router, Archer (give it 2 minutes), switch, access point, IDS PC.
The settings live in each device (the switch's only after its **Save**), so
nothing needs setting again. The IDS services start by themselves at boot.

## 4. Checks

1. On the VM: `ip -br addr show ens34` shows 192.168.50.135 (unplug and
   replug, or wait a minute, if it still shows an old address), and the
   dashboard opens.
   - If ens34 gets no address at all, port 8 is not passing normal traffic
     while it is the mirror destination. Then the IDS PC needs a second
     connection: a normal switch port into a second Ethernet port (or a USB
     Ethernet adapter) on the PC.
2. Laptop and a phone on the Linksys Wi-Fi: each gets a 192.168.50.1xx
   address from the Archer, `ping 192.168.50.1` answers and websites open.
   A 192.168.1.x address means the access point is handing out its own
   addresses: put it back in Bridge Mode.
3. On the VM, while the laptop pings:

       sudo tcpdump -i ens34 -nn icmp and not host 192.168.50.135

   shows the laptop's pings to the router: traffic that isn't the IDS's own.
4. The dashboard's test alert (a ping to 192.168.50.1) still arrives.
5. The Archer's status page shows the Internet connected with a
   192.168.10.x address.

On 25 Nov 2026, after the move: the VM reached .1, .2, .11 and a phone at
.165, about 380 mirrored packets a second arrived on `ens34`, and both
engines were alerting within seconds.

## Choosing what to mirror

The TL-SG3210 copies the chosen source ports to **one** of its own ports (8).

- **Every port except 8, ingress only** (the setup above). Every packet
  enters the switch through exactly one port, so copying what *enters* each
  port gives the IDS every packet that crosses the switch **once**: a
  phone's ping enters port 2 (the Linksys), the router's reply enters
  port 1. This covers
  the router, every device and device-to-device traffic on the switch.
- Don't use **Both** (ingress and egress) on more than one port: a packet
  entering one mirrored port and leaving by another is copied twice, and
  the engines raise its alerts twice.
- The IDS PC's own traffic (the VM and the Windows host, port 8) still
  reaches the IDS normally. Replies to it enter a mirrored port, so they
  arrive twice: once delivered, once as the copy (`ping` from the VM shows
  "+1 duplicates"). Traffic between other devices is seen once.
- Traffic that stays inside the Archer C6 (between its Wi-Fi devices, or its
  own yellow ports) never reaches the switch. That's why its Wi-Fi is off
  and test machines plug into the switch.
- The lab's traffic to the internet crosses the switch (into the Archer on
  port 1), so the IDS sees it, with each device's own 192.168.50.x address.
  The Archer's WAN side and the room router's network are not seen.
- Until 25 Nov 2026 the lab had no internet: the Archer answered every DNS
  lookup "Refused", and those made many of the alerts (about 2,500 every 10
  minutes on 19 Nov with the laptop and the IDS PC connected). With
  internet, lookups succeed and real browsing shows instead (about 10,500
  alerts an hour on 25 Nov with one phone browsing, no dropped packets).
  The routers' UPnP and ARP announcements still show as before.
- Logging in to the Archer, switch or Linksys pages goes over plain HTTP,
  so the engines flag it ("Basic Auth ... unencrypted", "Tomcat Auth Brute
  Force attempt (admin)", "Linksys Smart WiFi Information Disclosure"):
  correct detections of real traffic.
- Run attack tests only against 192.168.50.x addresses: the lab now has a
  way out, so a scan aimed at the wrong address reaches the room's network
  or the internet.

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

### The Linksys EA6300 access point

Linksys Smart Wi-Fi routers do it with **Bridge Mode** instead of the steps
above: DHCP and routing go off, and the router joins the lab by its
**Internet** port, not a LAN port.

1. Reset it (hold Reset 10 seconds with it on, until the power light is
   solid), then connect only the laptop to one of its LAN ports and open
   http://192.168.1.1.
2. The setup wizard stops at "Your Internet cable is not connected
   correctly" (then error 2318) because it wants internet. On the first
   page, tick the agreement box and use the **Manual configuration** link
   (or "I want to skip setup") at the bottom; the password is `admin`. If
   there is no such link, cable a LAN port of the room router to its yellow
   Internet port for a moment and let the wizard finish.
3. **Router Settings → Connectivity → Basic**: set the router password.
4. **Router Settings → Wireless**: Wi-Fi name and password, WPA2 Personal.
5. **Router Settings → Connectivity → Internet Settings**: Type of
   Internet Connection **Bridge Mode**, static IPv4 address
   **192.168.50.11**, mask 255.255.255.0, gateway and DNS 192.168.50.1.
   Apply; it restarts and stops answering at 192.168.1.1.
6. Its yellow **Internet** port → a free switch port (port 2). Its page is
   now at http://192.168.50.11; a phone on its Wi-Fi gets a 192.168.50.1xx
   address from the Archer.
7. Keep it off the lab until it's in Bridge Mode: with its own DHCP on, it
   would hand out addresses that clash with the Archer.

A router connected by its **WAN** port with its DHCP on would make a
separate network behind it (for example 192.168.60.x) and hide its devices
behind its one 192.168.50.x address (NAT): the IDS would see only that one
address. That's why routers are added as access points.
