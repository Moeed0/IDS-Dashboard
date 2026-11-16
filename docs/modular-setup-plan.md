# Modular setup plan

This plan covers three things:

- how to make the IDS setup modular and lighter, so that it can move to a
  Raspberry Pi and have new features added on top;
- what to change on the Pi itself;
- what is on GitHub, and what to keep in mind there.

It was written on 5 November 2026 from measurements on the lab VM, and
brought up to date on 16 November 2026.

## What runs today

| Part | What it does | Runs as |
|---|---|---|
| Snort 3.12.2 | Reads `ens38` with afpacket and 53,485 rules: the registered rules, their 4,686 shared-object (SO) rules and the built-in rules. OpenAppID names each flow's application. Writes `/var/log/snort/alert_json.txt` | `snort-lab.service` and its drop-in `daq-afpacket.conf` (afpacket, `--plugin-path` for the SO rules) |
| Suricata 8.0.3 | Reads `ens38` with af-packet, 2 capture threads, and 69,430 ET Open rules. Writes `/var/log/suricata/eve.json`, and pcap files of the flows that raised alerts | `suricata.service` |
| Collector | `src/live_dual_collector.py` reads both logs and stores the alerts in `ids_live.db`: the newest `IDS_ALERT_RETENTION` (600,000 on this VM), the older ones in `alert-archive/` for 30 days | `ids-collector.service` |
| Dashboard | `src/dashboard_api.py` serves the API and the React page (`web/`) on port 8501 | `ids-dashboard.service` |
| Export | The combined JSON (`ids.combined_detections`, schema 9.4), with offline rule and intel enrichment | Part of the dashboard |
| Rule updates | Suricata's rules every night (a reload, so capture goes on); Snort's registered rules, SO rules and OpenAppID detectors every week; each checked before it goes live | `ids-rule-update.timer`, 04:15 |
| Backup | Checks the database and keeps a gzipped copy, the newest 3 | `ids-backup.timer`, 03:30 |
| Test alert | A ping out of the capture card that both engines' rules flag, to prove capture, the rules and the collector work | `ids-test-alert.timer`, 5 past every hour |

The backup and the rule update wait until 15 minutes after a start-up when
they catch up a night the machine was off. The capture card is VMware's
vmxnet3; `deploy/pin-capture-interface.sh` keeps its name, `ens38`, and its
offloads off.

The service, timer and rule-update files are in [deploy/](../deploy/README.md).

## Memory and disk

**Memory**, as measured on 13 and 16 November:

| Part | Memory |
|---|---|
| Snort, with all its rules, the SO rules and OpenAppID | about 800 MB (OpenAppID about 190 MB of it) |
| Suricata, with all its rules, on 2 capture threads | about 820 MB (on 8 threads it started at 890 MB) |
| Collector | 21 MB |
| Dashboard | 52 MB |

The whole sensor needs about 1.7 GB. The VM has 7.3 GB, and the desktop and
browser take much of the rest; when memory runs short it swaps to a slow
virtual disk, which once held the collector up for 13 minutes after a
start-up.

**The database:** about 46,000 alerts a day in mid-November, at about 2.2 KB
each with its indexes (466,000 alerts take 1.04 GB). 600,000 alerts is about
13 days and about 1.3 GB; the older alerts go to the archive, in 10-day zips
kept for 30 days.

**Disk** written per day by the logs, before and after the 5 November
changes:

| Log | Before | After |
|---|---|---|
| Suricata `eve.json` | about 122 MB, 77% of it statistics | about 28 MB, plus the alerts that rule thresholds used to hide |
| Suricata `stats.log` | about 79 MB, every 8 s | about 11 MB, every 60 s |
| Suricata `fast.log` | about 3.5 MB, the same alerts as text | off |
| Snort `perf_monitor_base.csv` | one row a second while packets came | one row a minute |
| Snort `alert_json.txt` | about 8 MB, never rotated | the same, rotated weekly (8 kept) |

Since 12 November Suricata also keeps pcap files of the alerted flows, at
most 10 of 100 MiB.

**In the repo folder:**

| Folder | Size | Note |
|---|---|---|
| `data/intel` | 1.6 GB | `intel.db`, built by `scripts/download_intel_sources.py --build`. Since 16 November the build leaves out two full-text search tables nothing reads, so the next one is smaller |
| `data/lab/rules/ids_rules.db` | 398 MB | The rule index used for the export's enrichment, SO rules included |
| `backups/` | about 350 MB | The newest 3 nightly copies |
| `.venv` | 33 MB | From `requirements.txt` |
| `web/node_modules` | 105 MB | Needed only to build the page |

On 5 November everything the dashboard didn't use moved out of the repo
folder (3.25 GB: the Streamlit dashboard, the old collectors and pipelines,
the rule-documentation scrapers, old data and copies). On 16 November the
code and settings left over from removed features went too: the empty
`packets` table, the old intelligence worker's settings, and functions
nothing called.

## Making it modular

1. **One settings file per machine.** Done on 5 November 2026 for the
   collector, the dashboard and the rule index:
   - `.env` names the engines (`IDS_ENGINES`), their logs, their rules and
     config files (`IDS_SNORT_RULES`, `IDS_SNORT_CONFIG`,
     `IDS_SURICATA_RULES`, `IDS_SURICATA_CONFIG`), the interface, the LLM
     PC (`IDS_LLM_URL`) and the test alert's target
     (`IDS_TEST_ALERT_TARGET`); `.env.example` lists them all.
   - The rule counts are machine data, not settings: the rule update saves
     them in `.runtime/engine_rule_counts.json` (`IDS_RULE_COUNTS_FILE`).
   - Still to do: `IDS_DATA_DIR` (step 4), and building the engines' own
     settings from `.env` when installing (step 5). `ens38` is still
     written in the Snort drop-in and `suricata.yaml`, and the rules' folder
     (`/home/moeed824/snort-registered-test`) in `deploy/snort/snort.lua`.
     `deploy/install-services.sh` already fills in the folder and the user.
2. **Each engine optional.** Done on 5 November 2026. `IDS_ENGINES=suricata`
   (or `snort`) makes:
   - the collector read only that engine's log;
   - the dashboard show only that engine, without the "Both engines" tiles;
   - the rule index hold only its rules.

   Old alerts of an engine that no longer runs are left out, and they don't
   hold the latest complete time back.
3. **Features as add-ons.** Each screen is one data function in
   `ids.dashboard_data`, one API route and one React screen. Keep new
   features that way, each with a switch in `.env`, so the Pi can run only
   what it needs:
   - done: the LLM export (Download JSON and Send, `IDS_LLM_URL`), the
     hourly test alert (`IDS_TEST_ALERT_TARGET`, empty for none), and pcap
     of alerted flows (a Suricata setting);
   - still open: alerts by e-mail.

   The enrichment data (`data/intel`, the rule index) is the heaviest part,
   and only the export needs it.
4. **Data outside the code.** Still to do.
   - Keep the database, the intel databases, the rule index, the backups,
     the archive and the logs under `IDS_DATA_DIR` (for example
     `/var/lib/ids-dashboard`), not in the repo folder.
   - They are already built or downloaded by scripts (`build_rule_index.py`,
     `download_intel_sources.py`) and left out of git, so the code folder can
     go to GitHub as it is.
5. **Install from one script.** Done on 10 November 2026: `setup.sh` makes
   `.venv`, writes `.env` for the engines it finds, builds the page and the
   rule index, lets the collector read the logs, puts in the local rules,
   saves the rule counts, and installs the collector, the dashboard, the
   backup and the test alert. A release zip has the page built, so it needs
   no Node.js. Separate steps, as they need choices or sudo:
   `deploy/install-rule-updates.sh` (the oinkcode),
   `deploy/apply-suricata-settings.sh`, `deploy/apply-snort-config.sh` and
   `deploy/pin-capture-interface.sh`.
6. **Rule updates on a timer.** Done on 12 November 2026
   (`deploy/update-rules.sh`, `ids-rule-update.timer`):
   - Suricata every night: `suricata-update --no-test` with this lab's
     `enable.conf`, `disable.conf` and `modify.conf`, then a rule reload;
   - Snort every week: the registered rules with the oinkcode (kept in
     `/etc/ids/oinkcode`, root only), their SO rules copied to
     `/usr/local/lib/snort/so_rules`, and the OpenAppID detectors when
     snort.org has newer ones;
   - each checked (`snort -T` with the SO rules) before Snort restarts, the
     old ones put back if the check fails;
   - then the rule counts and the rule index, and a dashboard restart.

## Raspberry Pi

**Hardware**

- **Model:** a Pi 5 with 8 GB. Both engines with every rule need about
  1.7 GB, which grows with traffic, plus the system and the dashboard. A
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
  LuaJIT, PCRE2, hwloc). The registered rules come with SO rules built for
  `aarch64` too: set `so_build=aarch64` in `deploy/update-rules.sh`.
  OpenAppID's detectors are Lua, so they work as they are.
- **Suricata:** use the distribution's package, or build it.
- **Hyperscan:** it does not run on ARM. Both engines fall back to their
  Aho–Corasick matchers. Snort already uses `ac_bnfa`, its low-memory one.

**If memory runs short**, in this order. None of these removes a rule:

1. Turn off Snort's `appid` (about 190 MB), if the app names aren't used.
   The 164 app-detect rules then can't fire.
2. Set Suricata's `detect.profile` to `low` and `sgh-mpm-context` to
   `single`.
3. Use 1 Suricata capture thread instead of 2.
4. Make Suricata's `flow`, `stream` and `defrag` memcaps smaller.

**If disk runs short**, turn off the `eve.json` protocol records that
nothing reads yet (`dns`, `mdns`, `flow` and the others; about 25 MB a
day), or Suricata's pcap files. The dashboard reads only the alerts, but
those records may be useful for later features.

## On GitHub

The project is at `Moeed0/IDS-Dashboard` (the remote `public`), with:

- **Releases:** a version tag (`v1.2.1` is the latest) makes GitHub test the
  code, build the page and publish `IDS-Dashboard-<version>.zip`;
- **Tests:** every push runs the Python tests and the page's tests and build;
- **License:** MIT;
- **`.gitignore`:** `.env`, the databases and their `-wal`/`-shm` files,
  `.runtime/`, `backups/`, `alert-archive/`, the data built on each machine
  (`data/intel/`, `data/lab/rules/`), logs, captures and local tool settings;
  `web/.gitignore` leaves out `node_modules/` and `dist/`;
- **No secrets:** neither the API token, the NVD key nor the Snort oinkcode
  is in any file or in the history, and `.env` was never committed. The
  registered Snort rules aren't in it either: each machine downloads its own.

The team's `MaheenN31/Real-Time-Network-IDS-Dashboard` (the remote `origin`)
and the public demo `Moeed0/Real-Time-Network-IDS-Dashboard` are separate;
leave them as they are.

**Visible in the public repo**, as it is public:

- `/home/moeed824` in `deploy/snort/snort.lua` (the rules' folder);
- the lab's IP addresses, in the docs, tests and `config/lab_phases.json`;
- the commit authors' names and e-mail addresses.

**Fresh clone:** the tests that read the real rule index or the intel
database skip when those aren't built; the rest pass.
