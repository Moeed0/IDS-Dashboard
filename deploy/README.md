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
| `suricata/disable.conf` | `/etc/suricata/disable.conf` by `apply-suricata-settings.sh` | `suricata-update` leaves out ET's Conficker P2P rules (2009205–2009207), which fire on the LAN's mDNS |
| `apply-suricata-settings.sh` | | Alerts keep their payload and HTTP body as text, the packets of alerted flows go to pcap files (10 × 100 MiB at most), the Conficker rules go, and Suricata's logs are readable by root and this folder's owner only (`systemd/suricata.service.d/log-access.conf`). Backs up `suricata.yaml`, checks it, and puts it back if the check fails |
| `update-rules.sh` | | Fetches and loads the newest rules: Suricata's every night (`suricata-update`, then a reload), Snort's registered rules once a week with the oinkcode in `/etc/ids/oinkcode`, their compiled SO rules copied to `/usr/local/lib/snort/so_rules`, and Talos's free OpenAppID detectors in `/usr/local/lib/openappid` when snort.org has newer ones or they're missing (checked with `snort -T`, the old ones kept if it fails); then the dashboard's rule counts and rule index |
| `systemd/ids-rule-update.service`, `ids-rule-update.timer` | `/etc/systemd/system/` by `install-rule-updates.sh` | Runs `update-rules.sh` every night at 04:15 |
| `install-rule-updates.sh` | | Installs that timer, and asks once for the Snort oinkcode, kept in `/etc/ids/oinkcode` (root only, never in the repo); `--new-oinkcode` replaces it |
| `snort/snort.lua` | `/usr/local/etc/snort/snort.lua` by `apply-snort-config.sh` | Snort's settings: every registered rule, the SO rules, the local rules and the built-in rules on, OpenAppID (for the app-detect rules and `app_id`), HOME_NET `any`, statistics every 60 s, each alert's payload (`b64_data`) in its JSON |
| `rules/local.rules` | `/usr/local/etc/snort/local.rules` and `/etc/suricata/rules/local.rules` by `install-local-rules.sh` | 24 basic rules both engines load from the same text (SIDs from 1000001, messages "LOCAL …") |
| `install-local-rules.sh` | | Puts the local rules into both engines (`--remove` empties them again): adds the files to Suricata's `rule-files` and Snort's rules when missing, checks both engines, reloads Suricata while it runs, restarts Snort, and updates the dashboard's rule counts and rule index. `setup.sh` runs it |
| `apply-snort-config.sh` | | Installs `snort/snort.lua` and the `snort-lab` drop-in, checks it with `snort -T`, restarts Snort, and puts the old settings back if either step fails |
| `logrotate/snort` | `/etc/logrotate.d/snort` | Rotates Snort's alert log weekly; the collector reads what it missed from the rotated copies |

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
