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
| `scripts/import_offline_intelligence.py` | Builds the offline threat-intel database |
| `config/lab_phases.json` | The lab's attacker addresses, for the dashboard's warnings |
| `data/` | Data each machine builds or downloads ([data/README.md](data/README.md)) |
| `tests/` | The tests |
| `docs/` | The API and data ([docs/react-native-port.md](docs/react-native-port.md)), the export format and the modular plan |

## Setting up a machine

You need Ubuntu, or Raspberry Pi OS 64-bit, with Snort 3 and/or Suricata
installed and their rules in place; `deploy/README.md` shows this lab's
settings. You also need Python 3.13 and, to build the page, Node.js 22.

1. Get the code and its Python packages:

   ```bash
   git clone <this repository> && cd Real-Time-Network-IDS-Dashboard
   python3 -m venv .venv
   .venv/bin/pip install -r requirements.txt
   ```

2. Copy the settings and set this machine's values: the engines, the
   interface, and the logs, rules and config files.

   ```bash
   cp .env.example .env
   ```

3. Build the page:

   ```bash
   cd web && npm ci && npm run build && cd ..
   ```

4. Build the rule index the export uses:

   ```bash
   PYTHONPATH=src .venv/bin/python src/ids/build_rule_index.py
   ```

5. Install the collector and the dashboard as services:

   ```bash
   sudo deploy/install-services.sh
   ```

6. Open `http://<machine>:8501/`. The page asks for the API token,
   `IDS_API_TOKEN` in `.env`; the API creates one on its first start.

## Tests

```bash
.venv/bin/pip install -r requirements-dev.txt
PYTHONPATH=src .venv/bin/python -m pytest -q
```
