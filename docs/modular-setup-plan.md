# Modular setup plan

This plan covers three things:

- how to make the IDS setup modular and lighter, so that it can move to a
  Raspberry Pi and have new features added on top;
- what to change on the Pi itself;
- what to sort out before it goes to GitHub.

It was written on 5 November 2026 from measurements on the lab VM.

## What runs today

| Part | What it does | Runs as |
|---|---|---|
| Snort 3.12.2 | Reads `ens38` with afpacket and 48,757 rules; writes `/var/log/snort/alert_json.txt` | `snort-lab.service` and its drop-in `daq-afpacket.conf` |
| Suricata 8.0.3 | Reads `ens38` with af-packet and 69,309 rules; writes `/var/log/suricata/eve.json` | `suricata.service` |
| Collector | `src/live_dual_collector.py` reads both logs and stores the alerts in `ids_live.db` (the newest 200,000) | `ids-collector.service` |
| Dashboard | `src/dashboard_api.py` serves the API and the React page (`web/`) on port 8501 | `ids-dashboard.service` |
| Export | The combined JSON (`ids.combined_detections`), with offline rule and intel enrichment | Part of the dashboard |

The service and rule-update files are in [deploy/](../deploy/README.md).

## Memory and disk

**Memory**, as measured:

| Part | Memory |
|---|---|
| Snort, with all its rules | 648 MB |
| Suricata, with all its rules | 575 MB |
| Collector | 23 MB |
| Dashboard | 57 MB |

The whole sensor needs about 1.3 GB.

**Disk** written per day, before and after the 5 November changes:

| Log | Before | After |
|---|---|---|
| Suricata `eve.json` | about 122 MB, 77% of it statistics | about 28 MB, plus the alerts that rule thresholds used to hide |
| Suricata `stats.log` | about 79 MB, every 8 s | about 11 MB, every 60 s |
| Suricata `fast.log` | about 3.5 MB, the same alerts as text | off |
| Snort `perf_monitor_base.csv` | one row a second while packets came | one row a minute |
| Snort `alert_json.txt` | about 8 MB, never rotated | the same, rotated weekly (8 kept) |

The database is capped at 200,000 alerts, about 310 MB. Without the rule
thresholds about 79,000 alerts a day are expected, so that is about 2½ days.

**In the repo folder:**

| Folder | Size | Note |
|---|---|---|
| `data/intel` | 1.6 GB | `intel.db`. Its unused duplicate `intel.candidate.db` and the 241 MB of downloads it was built from were archived on 5 November |
| `data/lab/rules/ids_rules.db` | 407 MB | The rule index used for the export's enrichment |
| `.venv` | 565 MB, 32 MB without the Streamlit packages | Rebuilt from the new `requirements.txt` |
| `web/node_modules` | 98 MB | Needed only to build the page |

On 5 November 2026 everything the dashboard does not use moved out of the
repo folder, into `~/Real-Time-Network-IDS-Dashboard-unused-20261105/`, with
the same paths (3.25 GB). That covers:
- the Streamlit dashboard, the old collectors and pipelines, and their tests;
- the rule-documentation scrapers;
- old data, database copies and backups.

The export was checked to be the same before and after.

## Making it modular

1. **One settings file per machine.** Done on 5 November 2026 for the
   collector, the dashboard and the rule index:
   - `.env` names the engines (`IDS_ENGINES`), their logs, their rules and
     config files (`IDS_SNORT_RULES`, `IDS_SNORT_CONFIG`,
     `IDS_SURICATA_RULES`, `IDS_SURICATA_CONFIG`) and the interface;
     `.env.example` lists them all.
   - The rule counts are machine data, not settings: the rule update saves
     them in `.runtime/engine_rule_counts.json` (`IDS_RULE_COUNTS_FILE`).
   - `config/ids_sources.json`, with its `/home/moeed824` path, is gone.
   - Still to do: `IDS_DATA_DIR` (step 4), and building the engines' own
     settings (`ens38` in `snort.lua`, `suricata.yaml` and the Snort
     drop-in) from `.env` when installing (step 5).
     `deploy/install-services.sh` already fills in the folder and the user.
2. **Each engine optional.** Done on 5 November 2026. `IDS_ENGINES=suricata`
   (or `snort`) makes:
   - the collector read only that engine's log;
   - the dashboard show only that engine, without the "Both engines" tiles;
   - the rule index hold only its rules.

   Old alerts of an engine that no longer runs are left out, and they don't
   hold the latest complete time back.
3. **Features as add-ons.** Each screen is already one data function in
   `ids.dashboard_data`, one API route and one React screen. Keep new
   features that way:
   - packet capture;
   - alerts by e-mail;
   - an LLM dataset export.

   Give each one a switch in `.env`, so the Pi can run only what it needs.
   The enrichment data (`data/intel`, the rule index) is the heaviest part,
   and only the export needs it.
4. **Data outside the code.**
   - Keep the database, the intel databases, the rule index, the backups
     and the logs under `IDS_DATA_DIR` (for example
     `/var/lib/ids-dashboard`), not in the repo folder.
   - Build or download them with a script: `build_rule_index.py`, the intel
     fetchers.
   - Then the code folder stays small and can go to GitHub as it is.
5. **Install from `deploy/`.** Add a `deploy/install.sh` that sets up a new
   machine:
   - makes `.venv` and installs `requirements.txt`;
   - builds `web/`;
   - installs the engine changes (the Suricata changes,
     `suricata/modify.conf`, the Snort drop-in, logrotate);
   - installs the services.
6. **Rule updates on a timer.** Add a weekly systemd timer that:
   - runs `suricata-update --no-test` (HOME_NET `any` makes its own test
     fail; Suricata itself skips the 7 rules that fail);
   - fetches Snort's registered rules with the oinkcode, kept in a
     root-only file;
   - checks Snort with `snort -T`;
   - restarts both engines;
   - saves the engines' rule counts with `ids.config.write_rule_counts`,
     rebuilds the rule index and restarts the dashboard.

## Raspberry Pi

**Hardware**

- **Model:** a Pi 5 with 8 GB. Both engines with every rule need about
  1.3 GB, which grows with traffic, plus the system and the dashboard. A
  4 GB Pi can run one engine comfortably.
- **Storage:** a USB 3 SSD for the logs, the database and `data/`. Constant
  log writes wear out SD cards. Keep the system on the SD card or the SSD.
- **Network:** two ports. Use the built-in Ethernet for management and a USB
  3 Gigabit adapter for capture, fed by a switch mirror (SPAN) port or a
  network tap. A Pi does not see other machines' traffic the way the VM's
  virtual switch shows it.
- **Cooling:** active cooling. Detection keeps the CPU busy.

**System and engines**

- **System:** a 64-bit system (Raspberry Pi OS or Ubuntu Server arm64).
- **Snort:** build Snort 3 from source on arm64, as on the VM (libdaq,
  LuaJIT, PCRE2, hwloc). The registered rules' `so_rules` are x86 binaries;
  the text rules work.
- **Suricata:** use the distribution's package, or build it.
- **Hyperscan:** it does not run on ARM. Both engines fall back to their
  Aho–Corasick matchers. Snort already uses `ac_bnfa`, its low-memory one.

**If memory runs short**, in this order. None of these removes a rule:

1. Turn off Snort's `appid`, if the app name isn't used.
2. Set Suricata's `detect.profile` to `low` and `sgh-mpm-context` to
   `single`.
3. Use 2 Suricata threads instead of `auto`.
4. Make Suricata's `flow`, `stream` and `defrag` memcaps smaller.

**If disk runs short**, turn off the `eve.json` protocol records that
nothing reads yet (`dns`, `mdns`, `flow` and the others; about 25 MB a
day). The dashboard reads only the alerts, but those records may be useful
for later features.

## Before GitHub

Done on 5 November 2026:

- **`.gitignore`:**
  - `.env`, the databases and their `-wal`/`-shm` files, `.runtime/`, `.backups/`;
  - the data built on each machine (`data/intel/`, `data/lab/rules/`);
  - logs, captures and local tool settings.
  `web/.gitignore` leaves out `node_modules/` and `dist/`.
- **Size:** the biggest file kept is the rule documentation (9 MB); the
  intel and rule databases are built on each machine (`data/README.md`).
- **No secrets:** neither the API token nor the NVD key is in any file to be
  uploaded or in the git history, and `.env` was never committed. The Snort
  oinkcode is typed at a prompt and kept nowhere in the repo.
- **README:** what the project is, how it works, what is where, and how to
  set up a machine.
- **Requirements:** `requirements.txt` holds only what runs (Starlette,
  uvicorn), and `requirements-dev.txt` adds pytest.
- **Tests on a fresh clone:** the 11 tests that read the real rule index skip
  when it is not built; the rest pass.

Still to decide or do:

- **Where it goes:** this repo's remote is the team's
  `MaheenN31/Real-Time-Network-IDS-Dashboard`. The separate public demo copy
  pushes to `Moeed0/Real-Time-Network-IDS-Dashboard`; leave it as it is.
- **Personal details:** if the repo is public, note that these are visible:
  - `/home/moeed824` in `deploy/snort/snort.lua`
    (`RULE_PATH`);
  - the lab's IP addresses;
  - the commit authors' e-mail addresses.
- **A license**, and GitHub Actions that run the tests and the web build.
