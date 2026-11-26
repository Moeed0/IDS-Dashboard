# Deploy

The files that set up the IDS sensor on a machine: this VM now, a Raspberry
Pi later (see [docs/modular-setup-plan.md](../docs/modular-setup-plan.md)).
Nothing here holds a secret; the API token stays in `.env`.

| File | Installed as | What it does |
|---|---|---|
| `systemd/ids-collector.service` | `/etc/systemd/system/` by `install-services.sh` | Runs the collector at boot and after a crash |
| `systemd/ids-dashboard.service` | `/etc/systemd/system/` by `install-services.sh` | Runs the dashboard and its API on port 8501 |
| `systemd/ids-backup.service`, `ids-backup.timer` | `/etc/systemd/system/` by `install-services.sh` | A gzipped copy of the alert database every night at 03:30, or at the next start (`scripts/backup_database.py`) |
| `systemd/ids-test-alert.service`, `ids-test-alert.timer` | `/etc/systemd/system/` by `install-services.sh` | The hourly test alert at 5 past: one ping to `IDS_TEST_ALERT_TARGET` out of the capture card, and a check that each engine's alert on it is stored within 90 s (`scripts/send_test_alert.py`); the Overview shows the result |
| `systemd/snort-lab.service` | `/etc/systemd/system/snort-lab.service` | Runs Snort on the capture interface |
| `systemd/snort-lab.service.d/daq-afpacket.conf` | `/etc/systemd/system/snort-lab.service.d/` by `apply-snort-config.sh` | Snort reads packets with afpacket, so alerts are written at once, and loads the compiled SO rules (`--plugin-path /usr/local/lib/snort/so_rules`) |
| `pin-capture-interface.sh` | `/etc/systemd/network/10-ids-capture.link` | Keeps the capture card's name (`IDS_INTERFACE`, `ens38`) by its MAC address and its offloads off, so its adapter type can change in VMware (pcnet32 to vmxnet3) without Snort, Suricata or NetworkManager losing it. Run it before the change |
| `suricata/modify.conf` | `/etc/suricata/modify.conf` | `suricata-update` removes rule thresholds, so every match is logged, and rewrites the "not my servers" addresses of 7 ET rules, which with `HOME_NET any` wouldn't load, as `$EXTERNAL_NET` |
| `suricata/enable.conf` | `/etc/suricata/enable.conf` | `suricata-update` turns on every ET Open rule that is off by default |
| `suricata/disable.conf` | `/etc/suricata/disable.conf` by `apply-suricata-settings.sh` | Rules `suricata-update` leaves out: since 26 Nov 2026 "GPL MISC UPnP malformed advertisement" (2101384) and "SURICATA Ethertype unknown" (2200121), which fired about 40,000 times a day each on the routers' ordinary traffic; every other rule is on (the Conficker P2P rules 2009205–2009207 were off here until 17 Nov 2026) |
| `optimize-memory.sh` | `/etc/systemd/zram-generator.conf`, `/etc/sysctl.d/90-ids-memory.conf`, `/etc/systemd/system/user@.service.d/90-ids-oomd.conf`, `/etc/systemd/oomd.conf.d/90-ids.conf` | For a VM with 9-10 GB of RAM: compressed swap in RAM (zram, half the RAM) before the swap file; systemd-oomd kills the desktop session only after 60 s above 80% memory pressure (Ubuntu: 20 s, 50%); Suricata with one capture thread and detection profile `low` (same rules and alerts, loaded in half the time); printing off; and an unfinished Talos rule-documentation download restarted as a system service (`talos-download`), so a logout doesn't stop it. Undo steps are in the script |
| `apply-suricata-settings.sh` | | Captures on `IDS_INTERFACE` (from `.env`) with HOME_NET and EXTERNAL_NET `any`; alerts keep their payload and HTTP body as text, the packets of alerted flows go to pcap files (10 × 100 MiB at most), the rule selections (`enable.conf`, `disable.conf`, `modify.conf`) go to `/etc/suricata/`, and Suricata's logs are readable by root and this folder's owner only (`systemd/suricata.service.d/log-access.conf`). Turns on JA3, JA3S and JA4 TLS fingerprints (`ja3-fingerprints`/`ja4-fingerprints: yes`) and runs `install-tls-fingerprints.sh`. Backs up `suricata.yaml`, checks it, and puts it back if the check fails |
| `suricata/tls-fingerprints/` | `/etc/suricata/rules/tls-fingerprints.*` by `install-tls-fingerprints.sh` | Suricata's TLS fingerprint rules (SIDs 1000101–1000108, "LOCAL …"): a client fingerprint (JA4) new on the network, a TLS client new for a device (`tls-fingerprints.lua`: its JA3 with the extensions sorted, per address), and the fingerprints on the known-bad lists (`known-bad-ja4.txt`, `known-bad-ja3.txt`, `known-bad-ja3s.txt`, one per line). What Suricata has seen stays in `/var/lib/suricata/data` across restarts |
| `install-tls-fingerprints.sh` | | Checks the known-bad lists and writes them as Suricata's dataset files, installs the rules and the Lua script, adds the rules to `rule-files`, checks them with `suricata -T`, restarts Suricata (a reload keeps old lists) and updates the dashboard's rule counts and rule index. Run it with sudo after changing a list; `--no-restart` for `apply-suricata-settings.sh` |
| `update-rules.sh` | | Fetches and loads the newest rules: Suricata's every night (`suricata-update`, then a reload), Snort's registered rules once a week with the oinkcode in `/etc/ids/oinkcode`, their compiled SO rules copied to `/usr/local/lib/snort/so_rules`, and Talos's free OpenAppID detectors in `/usr/local/lib/openappid` when snort.org has newer ones or they're missing (checked with `snort -T`, the old ones kept if it fails); then the dashboard's rule counts and rule index |
| `systemd/ids-rule-update.service`, `ids-rule-update.timer` | `/etc/systemd/system/` by `install-rule-updates.sh` | Runs `update-rules.sh` every night at 04:15 |
| `install-rule-updates.sh` | | Installs that timer, and asks once for the Snort oinkcode, kept in `/etc/ids/oinkcode` (root only, never in the repo); `--new-oinkcode` replaces it |
| `snort/snort.lua` | `/usr/local/etc/snort/snort.lua` by `apply-snort-config.sh` | Snort's settings: its extractor's record of each TLS connection (site, version, cipher, curve, certificate) in `/var/log/snort/extractor_tls.json`, which the collector checks alerts with; every registered rule, the SO rules, the local rules and the built-in rules on except "(arp_spoof) unicast ARP request" (112:1, suppressed since 26 Nov 2026), OpenAppID (for the app-detect rules and `app_id`), HOME_NET `any`, statistics every 60 s, each alert's payload (`b64_data`) in its JSON |
| `rules/local.rules` | `/usr/local/etc/snort/local.rules` and `/etc/suricata/rules/local.rules` by `install-local-rules.sh` | 24 basic rules both engines load from the same text (SIDs from 1000001, messages "LOCAL …") |
| `install-local-rules.sh` | | Puts the local rules into both engines (`--remove` empties them again): adds the files to Suricata's `rule-files` and Snort's rules when missing, checks both engines, reloads Suricata while it runs, restarts Snort, and updates the dashboard's rule counts and rule index. `setup.sh` runs it |
| `new-vm.sh` | | A fresh Ubuntu VM end to end (`sudo deploy/new-vm.sh --interface <card>`): packages, Snort 3 built from source, both engines' rules, the lab's engine settings below, and `./setup.sh --with-intel` |
| `apply-snort-config.sh` | | Installs `snort/snort.lua`, the `snort-lab` service and its drop-in (capturing on `IDS_INTERFACE` from `.env`), makes Snort's two logs readable by this folder's owner (before Snort starts: it keeps a file's permissions), checks it with `snort -T`, restarts Snort, and puts the old settings back if either step fails |
| `logrotate/snort` | `/etc/logrotate.d/snort` | Rotates Snort's alert log and its extractor's TLS log weekly; the collector reads what it missed from the rotated copies |

Install the collector and the dashboard as services, as the user that owns
this folder (stop any copies started by hand first):

```bash
sudo deploy/install-services.sh
```

Then:

| To | Run |
|---|---|
| See whether they run | `systemctl status ids-collector ids-dashboard` |
| Restart the dashboard after a Python change | `sudo systemctl restart ids-dashboard` |
| Restart the collector after a change to it (it saves its place in the logs first) | `sudo systemctl restart ids-collector` |
| Read their output | `journalctl -u ids-collector -f` |
