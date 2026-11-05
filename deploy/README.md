# Deploy

The files that set up the IDS sensor on a machine: this VM now, a Raspberry
Pi later (see [docs/modular-setup-plan.md](../docs/modular-setup-plan.md)).
Nothing here holds a secret; the API token stays in `.env`.

| File | Installed as | What it does |
|---|---|---|
| `systemd/ids-collector.service` | `/etc/systemd/system/` by `install-services.sh` | Runs the collector at boot and after a crash |
| `systemd/ids-dashboard.service` | `/etc/systemd/system/` by `install-services.sh` | Runs the dashboard and its API on port 8501 |
| `systemd/snort-lab.service` | `/etc/systemd/system/snort-lab.service` | Runs Snort on the capture interface |
| `systemd/snort-lab.service.d/daq-afpacket.conf` | `/etc/systemd/system/snort-lab.service.d/` | Snort reads packets with afpacket, so alerts are written at once |
| `suricata/modify.conf` | `/etc/suricata/modify.conf` | `suricata-update` removes rule thresholds, so every match is logged |
| `suricata/enable.conf` | `/etc/suricata/enable.conf` | `suricata-update` turns on every ET Open rule that is off by default |
| `snort/snort.lua` | `/usr/local/etc/snort/snort.lua` by `apply-snort-config.sh` | Snort's settings: every registered rule and the built-in rules on, HOME_NET `any`, statistics every 60 s |
| `apply-snort-config.sh` | | Installs `snort/snort.lua`, checks it with `snort -T`, restarts Snort, and puts the old settings back if either step fails |
| `logrotate/snort` | `/etc/logrotate.d/snort` | Rotates Snort's alert log weekly |

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
