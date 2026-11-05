# Real-Time Network IDS Dashboard

A network intrusion detection sensor with a live web dashboard. Snort 3 and
Suricata 8 watch a network interface. A collector stores their alerts in
SQLite, and a small API serves a React dashboard and a combined JSON export
of both engines' alerts, for research and LLM datasets.

It runs on an Ubuntu VM in a lab today. It is set up so that it can move to
a Raspberry Pi and run one engine or both (see
[docs/modular-setup-plan.md](docs/modular-setup-plan.md)).

## How it works

```
network interface (afpacket)
   ├── Snort 3     → /var/log/snort/alert_json.txt
   └── Suricata 8  → /var/log/suricata/eve.json
                          │
          src/live_dual_collector.py   reads both logs as they grow
                          │
                     ids_live.db       SQLite, the newest IDS_ALERT_RETENTION alerts
                          │
          src/dashboard_api.py         API and the page, on port 8501
            ├── web/        the dashboard (Overview, Alert Explorer)
            └── /export     combined JSON, enriched from the rule index
                            and the offline threat-intel database
```

- **Overview:**
  - whether each engine and the collector run;
  - the last hour's alerts, and the packets one or both engines alerted on;
  - the last 24 hours, or a live chart of the last 15 minutes;
  - the top rules.
- **Alert Explorer:** every stored alert, searchable, and the combined JSON
  for a chosen time window
  ([docs/combined-json-format.md](docs/combined-json-format.md)).

## What is where

| Path | What it holds |
|---|---|
| `src/live_dual_collector.py` | The collector |
| `src/dashboard_api.py` | The API, which also serves the page |
| `src/ids/` | The shared code: settings, database, tailer, normalizer, screen data, combined export, rule and intel lookups, rule index builder |
| `web/` | The React page (TypeScript, Vite) |
| `deploy/` | systemd services, the engines' settings for this lab, log rotation ([deploy/README.md](deploy/README.md)) |
| `scripts/` | `download_intel_sources.py` downloads the threat-intel sources and builds the database from them with `import_offline_intelligence.py`; `save_rule_counts.py` saves the engines' rule counts |
| `config/lab_phases.json` | The lab's attacker addresses, for the dashboard's warnings |
| `data/` | Data each machine builds or downloads ([data/README.md](data/README.md)) |
| `tests/` | The tests |
| `docs/` | The API and data ([docs/react-native-port.md](docs/react-native-port.md)), the export format and the modular plan |

## Setting up a machine

This repository holds the dashboard: the collector, the API and the page.
The engines and their rules come from their makers, so set those up first.
It is tested on Ubuntu with Python 3.13, and with Node.js 22 to build the
page. For a Raspberry Pi, see
[docs/modular-setup-plan.md](docs/modular-setup-plan.md).

### 1. The engines

Install Snort 3, Suricata, or both, on a machine that sees the traffic: on a
real network, through a switch's mirror port or a network tap. Each must
write its alerts as JSON:

- **Snort:** run it with `-A alert_json -l /var/log/snort`. This lab's
  service is `deploy/systemd/snort-lab.service` with its afpacket drop-in;
  change `ens38` to your interface.
- **Suricata:** its default settings already write alerts to
  `/var/log/suricata/eve.json`. Set your interface under `af-packet:` in
  `/etc/suricata/suricata.yaml`.

`deploy/README.md` lists this lab's settings for both.

### 2. The rules

Neither rule set is in this repository; each comes from its maker.

- **Suricata (ET Open, free):**

  ```bash
  sudo suricata-update
  ```

  This lab also turns on every rule and logs every match: it copies
  `deploy/suricata/enable.conf` and `modify.conf` to `/etc/suricata/` first.
  With HOME_NET `any`, run `sudo suricata-update --no-test` instead: its own
  test fails on 7 rules, and it then puts the old rules back.

- **Snort (registered rules, free with an account):** these rules are
  licensed to you and may not be shared, so each machine downloads its own.
  1. Make an account on snort.org, and copy your oinkcode from your account
     page.
  2. Download the rules for your Snort version (`31200` is Snort 3.12), and
     unpack them:

     ```bash
     read -rsp "Snort oinkcode: " OINKCODE; echo; curl -fL -o snortrules.tar.gz "https://www.snort.org/rules/snortrules-snapshot-31200.tar.gz?oinkcode=$OINKCODE"; unset OINKCODE
     ```

     ```bash
     sudo mkdir -p /usr/local/etc/snort/registered && sudo tar -xzf snortrules.tar.gz -C /usr/local/etc/snort/registered
     ```

  3. Point Snort at them: `RULE_PATH = '/usr/local/etc/snort/registered/rules'`
     in `snort.lua` (this lab's is `deploy/snort/snort.lua`). Then check
     that Snort accepts them:

     ```bash
     sudo snort -c /usr/local/etc/snort/snort.lua -T
     ```

  Without an account, Snort's community rules (about 4,000) are free:
  `https://www.snort.org/downloads/community/snort3-community-rules.tar.gz`.

### 3. Let the collector read the logs

The engines write their logs as root, and the collector runs as your user.
Once both logs exist, give your user read access (this uses the `acl`
package):

```bash
sudo setfacl -m u:$USER:r /var/log/snort/alert_json.txt /var/log/suricata/eve.json
```

```bash
sudo setfacl -d -m u:$USER:r /var/log/snort /var/log/suricata
```

The second command keeps new log files readable too.

### 4. The dashboard

1. Get the code and its Python packages. If your `python3` is not 3.13, use
   `python3.13`.

   ```bash
   git clone https://github.com/Moeed0/IDS-Dashboard.git && cd IDS-Dashboard
   ```

   ```bash
   python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
   ```

2. Copy the settings. Then set this machine's values in `.env`: the engines
   it runs (`IDS_ENGINES`), their logs, and their rules and config files
   (`IDS_SNORT_RULES` is the `rules` folder from step 2).

   ```bash
   cp .env.example .env
   ```

3. Build the page:

   ```bash
   cd web && npm ci && npm run build && cd ..
   ```

4. Build the rule index, which the combined export uses for each rule's
   text:

   ```bash
   PYTHONPATH=src .venv/bin/python src/ids/build_rule_index.py
   ```

5. Save how many rules each engine loaded, which the Overview shows. Use
   your own Snort number, from the "total rules loaded" line of `snort -T`;
   Suricata's is read from its log.

   ```bash
   .venv/bin/python scripts/save_rule_counts.py --snort 48757 --suricata-log
   ```

6. Optional: build the threat-intel database, for the CVE, EPSS,
   known-exploited and ATT&CK details in the combined export. It downloads
   about 300 MB from NVD, FIRST, CISA and MITRE, and builds a 1.6 GB
   database in a few minutes. Run it again whenever you want fresher data.
   Without it the export still works, without those details.

   ```bash
   .venv/bin/python scripts/download_intel_sources.py --build
   ```

7. Install the collector and the dashboard as services, which start at
   boot:

   ```bash
   sudo deploy/install-services.sh
   ```

8. Open `http://<machine>:8501/`. The page asks for the API token,
   `IDS_API_TOKEN` in `.env`, which the API creates on its first start.

## Tests

```bash
.venv/bin/pip install -r requirements-dev.txt
PYTHONPATH=src .venv/bin/python -m pytest -q
```
