# Moving the dashboard to React Native

The dashboard has two screens, Overview and Alert Explorer. Each screen
only lays out what the functions in `src/ids/dashboard_data.py` return. Those
functions have no UI code, read the live database read-only and return plain
JSON values: dicts, lists, strings, numbers and `null`. All times are epoch
milliseconds, UTC.

React Native cannot run Python, so the app gets this data from a small HTTP
API on the IDS machine, `src/dashboard_api.py`. Each endpoint returns what one
of these functions returns, so the app shows the same data as the React web
page. (The first dashboard, in Streamlit, was removed on 5 November 2026.)

## The React web page (`web/`)

A React web page with both screens (Overview, Alert Explorer with the
combined JSON export) is in `web/`: Vite, React 19 and TypeScript, with no
other packages (the chart is drawn as SVG). It gets its data from the API
only; the API serves the built page at `/`, so one process on port 8501 gives
both the page and the data.

```bash
cd ~/Real-Time-Network-IDS-Dashboard/web && npm install && npm run build
```

Then open `http://<IDS machine>:8501/`. The page asks once for the API token
(`IDS_API_TOKEN` in `.env`) and keeps it in that browser. Rebuild after
changing anything in `web/src`; the API picks up the new build on its next
request. It sends the page itself with `Cache-Control: no-cache`, so
browsers check it again on every visit and show a new build at once (the
scripts and styles get new names each build, so they can be kept). For development, `npm run dev` serves the page with live reload on
port 5173 and passes the API paths to the API on port 8501.

Node.js 22 (Ubuntu's `nodejs` and `npm` packages) builds it. `web/node_modules`
and `web/dist` are not kept in git. The screens are described below; a React
Native app can reuse `web/src/api.ts` (types and calls) and `web/src/time.ts`
(PKT times) as they are.

## Running the API

Since 5 November 2026 the API runs as the systemd service
`ids-dashboard.service` and the collector as `ids-collector.service`. Both
start at boot and restart after a crash; `deploy/install-services.sh`
installs them (see [deploy/README.md](../deploy/README.md)). After a Python
change, restart the API:

```bash
sudo systemctl restart ids-dashboard
```

To run it by hand instead, stop the service first
(`sudo systemctl stop ids-dashboard`), then:

```bash
cd ~/Real-Time-Network-IDS-Dashboard && .venv/bin/python src/dashboard_api.py --host 0.0.0.0 --port 8501
```

It needs Starlette and uvicorn (`requirements.txt`). Its settings come from
`.env` (see
`.env.example`), read when it starts:

- the database the collector writes (`IDS_DB_FILE`) and the alert retention
  (`IDS_ALERT_RETENTION`);
- the engines this machine runs (`IDS_ENGINES`: `snort`, `suricata` or
  both) and their config files (`IDS_SNORT_CONFIG`, `IDS_SURICATA_CONFIG`),
  for HOME_NET;
- how many rules each engine loaded, from `IDS_RULE_COUNTS_FILE`
  (`.runtime/engine_rule_counts.json`, saved by the rule update).

Until 5 November 2026 the rule counts and the engines' files were in
`config/ids_sources.json`, which is gone.

- **One engine or both.** Every engine-keyed record (`engines`, `alerts`,
  `rules`, `running`) holds only the engines in `IDS_ENGINES`, which
  `/options` lists. A machine running Suricata alone gets no `snort` keys,
  and Snort's older stored alerts are left out of every screen and of the
  latest complete time. The page then hides the "Both engines" and "One
  engine only" tiles.

- **Token.** Every endpoint but `/health` asks for
  `Authorization: Bearer <token>`; a missing or wrong token gets 401. The
  token is `IDS_API_TOKEN` in `.env` (which git ignores); the first start
  creates one there, short enough to type: four groups of four letters and
  digits, such as `k7m2-x9qa-3fz8-p4wd` (no i, l, o or u). To replace it,
  run `.venv/bin/python src/dashboard_api.py --new-token` and restart the
  API; each browser then asks for the new one. The app keeps it in its
  settings, not in its code. For testing, `IDS_API_REQUIRE_TOKEN=false` in
  `.env` lets every request in without a token (the page then never asks),
  so anyone who can reach port 8501 sees the alerts; `true` asks again.
- **Network.** `--host 0.0.0.0` listens on every network the VM has; use
  `--host 127.0.0.1` to keep it to the VM. Another computer opens
  `http://192.168.50.142:8501/` on the lab network (the VM's ens38, which
  Snort and Suricata watch, so they see that traffic too), or comes in
  through VMware's NAT network (ens34, 192.168.141.128, not watched) when
  VMware forwards port 8501 from the computer it runs on. Ubuntu's firewall
  (ufw) is on; `sudo ufw status` shows whether it lets 8501 in. Keep the API
  off the public address of the internet connection.
- **Browsers.** The API allows any web origin (for Expo web); the token is
  what protects the data.
- **Errors.** `{"error": "…"}` with 400 (a bad query parameter), 401 (token),
  404 (no alert stored yet, for the export) or 503 (the database cannot be
  read).

## Endpoints

| Endpoint | Function | Returns |
|---|---|---|
| `GET /health` | | `{"ok": true}`, without a token |
| `GET /options` | | The choices the screens offer (below) |
| `GET /overview?step_minutes=&top_rules_length=` | `overview(db_path, ids_sources, alert_retention=…, step_minutes=…, top_rules_length=…)` | Overview screen data |
| `GET /status` | `status(db_path, state_file)` | Whether the IDS stores alerts now, for the status panel |
| `GET /live` | `live(db_path)` | The Overview's live chart: the last 15 minutes in 30-second steps |
| `GET /alerts?<filters>&page=&page_size=` | `alerts(db_path, filters=AlertFilter(…), …)` | One page of alerts, newest first |
| `GET /alerts/values` | `filter_values(db_path)` | The protocols, classes, services and apps the filters offer |
| `GET /alerts/{id}` | `alert_detail(db_path, id)` | One alert, whole, for the side panel |
| `GET /rule-pairs` | `rule_pairs(db_path)` | The last hour's rules both engines fired on one packet, for the Alert Explorer |
| `GET /export/selection?<filters>` | `selection(db_path, AlertFilter(…))` | What a download or send of the filtered alerts would hold |
| `GET /export/selection/file?<filters>` | `selection_export(db_path, AlertFilter(…))` | The combined JSON file of the filtered alerts |
| `POST /export/selection/send?<filters>` | `selection_export(…)`, then a POST to `IDS_LLM_URL` | Sends that file to the LLM PC |
| `GET /export/window?length=&end_ms=` | `export_window(db_path, length, end_ms)` | Start and end of a combined export of a whole window |
| `GET /export?length=&end_ms=` | `combined_export(db_path, …)` | The combined JSON file for that window |
| `GET /archive` | `archive_contents(archive_dir)` | The archive's zips and day files, for the Alert Explorer |
| `GET /archive/{name}` | `archive_file(archive_dir, name)` | One of them, as a download (404 for any other name) |

`/options` gives the fixed choices, so the app does not repeat them:

```json
{"engines": ["snort", "suricata"],
 "export_lengths": ["5 minutes", "10 minutes", "15 minutes", "…", "7 days"],
 "default_export_length": "15 minutes",
 "time_ranges": [{"label": "Last 5 minutes", "ms": 300000}, "…",
                 {"label": "All stored", "ms": null}],
 "page_sizes": [10, 25, 50, 100, 250],
 "last_choices": [5, 10, 20], "max_last": 150000,
 "send_to": "192.168.50.20:8000",
 "chart_steps": [5, 10, 15], "default_chart_step": 15,
 "live_step_seconds": 30,
 "default_top_rules_length": "1 day",
 "time_zone": "Asia/Karachi"}
```

## Overview

```json
{
  "complete_end_ms": 1793694999000,
  "alert_retention": 200000,
  "engines": {
    "snort": {"newest_ms": 1793694999066, "alerts": 20112, "oldest_ms": 1793538059105,
              "rules": 48661, "home_net": "any", "external_net": "any",
              "unmatched_lab_attackers": []},
    "suricata": {"…": "same fields"}
  },
  "last_hour": {"start_ms": 1793691399000, "end_ms": 1793694999000, "off": [],
                "alerts": {"snort": 483, "suricata": 758},
                "packets": 824, "both": 332, "snort_only": 93, "suricata_only": 399},
  "last_day": {"start_ms": 1793608200000, "end_ms": 1793694600000, "step_ms": 900000,
               "alerts": {"snort": [118, 121, "…96 counts"], "suricata": ["…"]},
               "off": [[1793454454000, 1793676089000]]},
  "top_rules": {"length": "1 day", "start_ms": 1793608599000, "end_ms": 1793694999000,
                "rules": {"snort": [{"rule": "116:444", "gid": 116, "sid": 444, "rev": 1,
                                     "message": "(ipv4) IPv4 option set",
                                     "alerts": 6640}, "…up to 10"],
                          "suricata": ["…"]}}
}
```

What the screen shows:

- **Status**: one strip at the top, from `/status` (below): first the
  status in colour (green "Live, storing alerts now", or what is wrong, as
  the panel's summary says it), then a cell for each engine with a green dot
  while it runs (red when stopped, grey when that is not known; `running`),
  how long ago its newest alert was (amber after 30 minutes) and its
  `rules`, then the collector, its dot and how long ago it last stored
  alerts (`collector_saved_ms`; amber after 5 minutes).
- **Warnings**: an engine with no `newest_ms`, or one more than 30 minutes
  old: "No Snort alert stored for 2 h. Check Snort and
  live_dual_collector.py." An engine with `unmatched_lab_attackers`: its
  EXTERNAL_NET keeps its rules from matching those lab attackers.
- **Last hour** (`null` when no alert is stored): tiles for alerts per
  engine, packets with alerts, packets both engines alerted on (with their
  share of the packets), and packets only one engine alerted on. The rules
  behind "Both engines" are in the Alert Explorer (`/rule-pairs`).
- **Last 24 hours** (`null` likewise): a line chart, one line per engine, of
  `alerts[engine][i]` at `start_ms + i * step_ms`; Snort `#3987e5`, Suricata
  `#d95926` on a dark background (`#2a78d6` and `#eb6834` on a light one).
  `step_minutes` (5, 10 or 15; 15 when left out) sets the time between the
  points; the page keeps the user's choice in that browser. The chart's
  heading is its dropdown, in the heading's type: "Alerts per 30 seconds"
  (the live chart, `live_step_seconds` from `/options`), "Alerts per 5
  minutes", "… 10 minutes" or "… 15 minutes". The time axis shows that the
  first covers the last 15 minutes and the others the last 24 hours, and
  "Live" is left to the status panel. Until 6 November 2026 the heading said
  "Last 24 hours" for every step, with a small "Alerts per" dropdown beside
  it that read like three time ranges, and the live choice was called
  "Live". The lines are
  named at their ends, with no legend. The chart is small while each
  engine's counts stay near their usual level and grows by itself when a
  burst rises above it: from twice the engine's median count to six times,
  it goes from its small to its full height. The side axis has up to 3 grid
  lines on the small chart and up to 5 on the tall one, a whole 1, 2, 2.5 or
  5 times a power of ten apart (5, 10, 25, 50, 100, …; 2.5 itself is never
  used), with the top line the first at or above the highest count:
  "0, 1,000, 2,000" or "0, 50, 100, 150". Until 6 November 2026 the lines
  were set fractions of the top, which gave counts like 62.5 and 187.5.
- **Machine off**: `off` in the last hour, the last 24 hours and `/live`
  lists each time the IDS machine was off that overlaps them, whole (it may
  begin before them), as `[from_ms, to_ms]`: from one boot's last journal entry to the next boot's
  first (`journalctl --list-boots`, read once when the API starts; a
  suspended machine is not found). The chart shades them, labels them
  "Off" and leaves its lines out over a step wholly inside one, instead of
  drawing 0, and the line under the chart says "Machine off: Sat 7 Nov
  17:47 – Tue 10 Nov 11:21 (65.6 h)". The Last hour section says how many
  of its minutes the machine was off. An engine stopped while the machine
  runs is not shown this way; the status panel shows it while it lasts.
- **The live chart**, the dropdown's first choice, before the three 24-hour
  ones (also kept in that browser). See "Live chart" below.
- **Top rules** (`null` likewise): each engine's most frequent rules over the
  last `top_rules_length` (one of the export lengths, `1 day` when left out),
  as a list (rule as `gid:sid:rev`, alerts, message), one line a rule like
  the Alert Explorer's, with a bar behind each count in the engine's colour,
  as long as its share of the busiest rule's; a rule that fired with two
  revisions has a row for each. `rule` is the SID with a GID other than 1
  first, as the combined export names rules.

The last hour, the last 24 hours and the top rules end at `complete_end_ms`,
the latest time up to which both engines' alerts are stored (one engine's can
be stored later than the other's); their packet counts match the combined
export's.

### Live chart

`GET /live`, every 5 seconds while the chart's live choice ("Alerts per 30
seconds") is on:

```json
{"checked_ms": 1793862463000, "window_ms": 900000,
 "start_ms": 1793861550000, "step_ms": 30000,
 "alerts": {"snort": [3, 9, 1, "…"], "suricata": [4, 15, 2, "…"]},
 "off": []}
```

`alerts[engine][i]` is that engine's alerts in the 30 seconds from
`start_ms + i * step_ms`. The steps start at whole half minutes, so a step's
count stays the same from one request to the next; the first one starts
before the window.

Each engine's list runs up to its own latest complete time, not both engines'
as on the rest of the Overview, so the lists can differ in length. Both lines
run nearly up to now while the engines and the collector keep up. One whose
alerts are stored late (while it restarts, say) ends earlier until it catches
up.

The chart:

- **Moving with the clock:** the time axis ends at the IDS machine's time
  now, `checked_ms` plus the time since the answer came, and the chart
  redraws every second.
- **Edges:** points that move past the left edge are cut off.
- **Labels:** the time is labelled every 2 minutes, and the heading (the
  chart's dropdown) says "Alerts per 30 seconds". It said "Last 15 minutes"
  until 5 November 2026 and "Live" until 6 November.
- **Hover:** the hover box lists only the lines that reach that point.
- **Height:** it grows on a burst as the 24-hour chart does.

## Status panel

`GET /status`, every 10 seconds, for the Overview's status strip (above)
and a panel down its right side (above the screen on a narrow one) with what
is stored, the drops, the disk and HOME_NET. The Alert Explorer takes the
whole width and has neither: there a warning line over the filters says what
is wrong, and nothing while the IDS is live.

```json
{"checked_ms": 1793792210825,
 "running": {"snort": true, "suricata": true, "collector": true},
 "collector_saved_ms": 1793792209007,
 "complete_end_ms": 1793792171000,
 "alert_retention": 200000,
 "engines": {"snort": {"…": "as on the Overview"}, "suricata": {"…": "…"}},
 "capture": {"snort": {"packets": 4612, "dropped": 0, "minutes": 60},
             "suricata": {"packets": 4280, "dropped": 0, "minutes": 60}}}
```

`test_alert` (not in the example above) is the last hourly test alert
(`scripts/send_test_alert.py`), or `null`: `{"sent_ms", "source", "target",
"answered", "wait_seconds", "engines": {engine: {"rule", "time_ms",
"stored_after_s"} or null}, "ok"}`. The strip shows it; a test that one
engine missed, under two hours old, makes the headline "Test alert missed".

`storage` (not in the example above) is `{"disk_free", "disk_total",
"database", "archive", "backups"}` in bytes: the disk the database is on,
the database with its write-ahead log, the alert archive, and
`backups: {"count", "bytes", "newest_ms", "checked_ms", "problem"}` for the
nightly backups (`null` when `IDS_BACKUP_KEEP` is 0); `checked_ms` is when
the database was last checked, before a backup, and `problem` what the check
found (`null` when whole; both `null` before the first check). The panel shows "Disk: 19.8 GB free of 52.5
GB", what the alerts take, and how old the newest backup is. Under 2 GB or
5% free the line turns red and the panel's headline says "Disk almost
full"; a backup over 36 hours old turns red too. The backup line ends
", database OK" after a passed check; a `problem` is a red "Database damaged:
run scripts/restore_backup.py" line and the headline "Database damaged".

`capture` is each engine's packets and dropped packets over the last hour
(`minutes` covered, fewer after it started), from the statistics the
engines write every minute: Snort's perf_monitor file
(`IDS_SNORT_PERF_FILE`, counts for each minute) and Suricata's `stats.log`
(`IDS_SURICATA_STATS_FILE`, totals since it started, which leaves out
counters that are 0). An engine whose file can't be read is `null`. A
dropped packet is one the engine never looked at, so its alerts are
missing. The panel shows "Dropped packets, last hour" with each engine's
"0 of 4,612"; more than 0 turns it red.

`running` says whether Snort, Suricata and `live_dual_collector.py` run on
the IDS machine (from `/proc`; `null` when it cannot be read).
`collector_saved_ms` is when the collector last saved its place in the
engines' logs, which it does each time it stores alerts. `engines` is the
Overview's.

The panel shows at its top "Live"; "No new alerts" after 5 minutes without
one stored; "Partly working" when an engine is stopped; "Not updating" when
the collector is stopped or the latest `/status` request failed. Then the
stored alerts (total, per engine, since when, how many are kept) and each
engine's HOME_NET. Snort, Suricata and the collector, with their dots, are
the Overview's first row. One `/status` request feeds both.

When the IDS machine or its API stops answering:

- Each request has a 15-second limit, and no new request is sent while one
  waits. A request that gets no answer fails ("No answer from the IDS
  machine") instead of being replaced unnoticed. One that cannot be sent
  fails at once ("Cannot reach the IDS machine: …").
- The panel then says "Not updating", the reason, and how long ago the
  last answer came ("Updated 40 s ago"). The dots turn grey, because
  whether the programs run is not known.
- The "… ago" times count on with the device's clock, between answers and
  when none comes. They use the IDS machine's time in the last status
  (`checked_ms`) plus the time since it came, so the two clocks need not
  agree.
- The page fetches again as soon as it is shown after being hidden, because
  browsers slow down hidden pages' timers.

## Alert Explorer

```json
{
  "total": 9924, "matching": 9924, "page": 1, "pages": 397, "page_size": 25,
  "rows": [
    {"id": 229839, "engine": "snort", "time_ms": 1793694999066, "rule": "112:1",
     "gid": 112, "sid": 1, "rev": 1,
     "message": "(arp_spoof) unicast ARP request", "class": null, "severity": 3,
     "protocol": "ARP", "service": null, "app": null, "src": null, "dst": null, "both": false}
  ]
}
```

The filters (`<filters>`), the same for the list, the download and Send;
each one left out takes every alert:

- `engine` is `snort`, `suricata` or left out for both. The dashboard shows
  two lists side by side (one call per engine) or one combined list.
- `range` is one of the time range labels (Last 5, 10, 15 or 30 minutes,
  Last hour, Last 24 hours, Last 7 days, Last 30 days, All stored); the API
  counts it back from its own clock, which the stored times follow.
  `since_ms` (epoch ms) can be sent instead, and `until_ms` ends the range.
- `search` matches the message, the rule as the screens show it
  (`116:444:1`), the class, protocol,
  service, app, either endpoint (`192.168.50.1:53`) or the PKT time
  (`2026-11-03 12:40`), in any case.
- `severity` is one or more of 1 to 4 (`1,2`); `protocol` (`UDP`), `class`
  (`Potentially Bad Traffic`), `service` (`dns`) and `app` (`IGMP`: the
  application Snort's OpenAppID named; Suricata's alerts have none) take that
  value in any case, from the lists `GET /alerts/values` gives (the most common first;
  "none" and "unknown" are left out).
- `rule` is a SID (`2001119`), `gid:sid` (`116:444`) or `gid:sid:rev`.
- `source` and `destination` are an address (`192.168.50.122`, `fe80::1`), a
  network (`192.168.50.0/24`) or an IPv4 address's first parts with a dot
  (`192.168.50.`, the same /24); `port` is a port on either side.
- `last` keeps only the newest that many (1 to `max_last`): `total` is then
  at most `last`, `matching` how many match without it, and the pages stop
  at the last of them. With `each=1` (download and send only) it is the
  newest that many of each engine, as the side-by-side lists show them.
- `page` starts at 1; `page_size` is 1 to 250. A page past the last returns
  the last page. A filter the API can't read is 400 with what it takes, such
  as `{"error": "source must be an address or a network, like
  192.168.50.122, 192.168.50.0/24 or 192.168.50."}`.
- `rule` is the SID, with the GID first when it is not 1; `gid`, `sid` and
  `rev` are the rule's numbers (`rev` is `null` when the engine gave none),
  which the screens show as `gid:sid:rev`. `severity` is 1
  (most severe) to 4. `src` and `dst` are `address:port`, `[IPv6]:port`, the
  address alone (no ports), or `null` (no IP addresses, such as ARP).
- `uid` is the alert's UID, 7 characters (`07ATG0K`), in Crockford's Base32
  (digits and capitals without I, L, O and U, so the case doesn't matter
  and UIDs sort by time). Each minute, counted from 1 Nov 2026 UTC, has
  16,384 numbers, from minute × 16,384. The collector numbers the alerts as
  it stores them, in time order: each new UID is the larger of its minute's
  first number and the last UID given + 1, so a quiet minute's alerts get
  its numbers in order, UIDs only go up, and none is given twice, even
  after the archive or a restored backup (the last UID is also kept in
  `.runtime/last_uid`). Past 16,384 alerts in a minute, the UIDs count on
  into the next minutes' numbers until a quieter time catches up. Seven
  characters last until late October 2030, and later UIDs take an eighth.
  Unlike `id`, which a restored backup counts from again, it never names
  two alerts. It is stored as its number, and the alert archive keeps its
  characters.
- `packet` names the row's packet: the `uid` of its first stored alert, so
  every alert on one packet has the same packet ID, in each engine's list
  and the combined one. It is worked out when the list is read, as `both`
  is, and not stored (Snort and Suricata alerts aren't grouped in the
  database). A page's rows are grouped by packet: the packets in the
  order of their newest row, each packet's rows together (Snort's first).
  The dashboard shows it as a Packet column and gives every other packet's
  rows a light shade, so the rows of one packet read as one; a packet keeps
  its shade from one refresh to the next. A packet whose alerts fall on two
  pages has rows on both.
- `severity` is shown as three circles, filled as the alert is more severe:
  3 filled (red) is severity 1, 2 (orange) is 2, 1 (amber) is 3, and none is
  4, not critical. The number is in the hover text.
- `both` is `true` when both engines alerted on the row's packet, matched
  as for the Overview's "Both engines" among the alerts stored within a
  millisecond of it; always `false` with one engine.
- Rows the dashboard shows: time (the time of day, with the date only when
  it is not today; the whole time on hover), both (a ✓; with both engines only), rule
  (`gid:sid:rev`, such as `1:2009206:4`; `gid:sid` without a revision),
  severity, message (side by side); time, engine, both, rule, severity,
  protocol, source, destination, message (combined). Page 1 is fetched
  again every 10 seconds; other pages stay as they are, so that their rows
  don't move. The page has no search or rows-per-page choice (it sends no
  `search`, and 25 rows a page): every stored alert, newest first, unless
  the filters or "Show the newest" narrow it. Two toolbars stand over the
  lists. The first: time (Any time, or the last 5 minutes to 30 days),
  engine, severity as four buttons of circles, "More filters" (with how many
  of its filters are set) and "Clear" while any filter is set, and the
  "Side by side" / "Combined" buttons at its end. "More filters" opens a row
  of the others: protocol, class, service, app, rule, source, destination, port
  (the list boxes keep one width, a long class ending in "…"). A filter
  that is set is outlined. The second: "Show the newest" 5, 10 or 20, or
  any number typed in (none chosen shows every alert, and a chosen number
  clicked again goes back to that), with "Download JSON" and "Send" at its
  end. Each list's name and count stand on one line with its paging (the
  rows shown, then newest «, newer ‹ and older ›). "Both engines: rule
  pairs" and "Old alerts" show only their headings until opened. The
  layout, the "More filters" row and the folds are kept as left in that
  browser; the filters last while the page is open. Each row is one line,
  so that the
  two lists side by side line up: a message too long for its column ends in
  "…" and shows whole on hover.

### One alert, whole

A row clicked (or Enter on it) opens a panel down the right side:
`GET /alerts/{id}` (404 for an id no alert has).

```json
{"alert": {"id": 557556, "engine": "suricata", "…": "as a row of the list"},
 "same_packet": [{"id": 557557, "…": "the other alerts on its packet"}],
 "rules": {"suricata:2009205": {"why_triggered": "…", "rule_text": "…", "ids_output": {}}},
 "packets": [{"packet": 1, "time": "…", "suricata": [{"rules": ["…"], "ids_output": {}}]}]}
```

- `alert` and `same_packet` are rows as the list gives them; `rules`, `cves`,
  `attack_techniques`, `flows` and `packets` are what the combined JSON gives
  for that one packet (docs/combined-json-format.md), each left out when
  empty.
- The panel shows the whole message, time, engine, rule (with a link that
  puts it in the Rule filter), class, protocol and service, the app, both endpoints,
  the alert's and the packet's IDs; the other alerts on the packet, each a
  link that opens it; the alert's rule (why it fired, its text, and the rest
  under its own headings); the CVEs and techniques; and the packet's entry
  as JSON. Esc or ✕ closes it; the row it shows is outlined.
- In the lists the headings stay in view while the page is scrolled, and a
  row that came in since the last answer lights up for a moment (page 1 of
  an unchanged list only).

### Both engines: rule pairs

Below the lists, with both engines, folded: `GET /rule-pairs` every 30
seconds while it is open.

```json
{
  "start_ms": 1793952002000, "end_ms": 1793955602000,
  "pairs": [
    {"snort": {"gid": 116, "sid": 444, "rev": 1, "message": "(ipv4) IPv4 option set"},
     "suricata": {"gid": 1, "sid": 2200007, "rev": 2, "message": "SURICATA IPv4 padding required"},
     "packets": 273}
  ]
}
```

- The last hour up to the latest complete time, as the Overview's "Both
  engines" counts it: up to 10 pairs of a Snort rule and a Suricata rule
  that fired on one packet, with how many packets, the most first. A packet
  with two rules of an engine counts for each of them.
- The times are `null` before any alert is stored, and `pairs` is empty
  with one engine.
- The table shows each rule as `gid:sid:rev` with its message, then the
  packets.

### Click a rule

A rule in the Overview's top rules or in the rule pairs is a link: it opens
the Alert Explorer (or stays there) with the rule, as `gid:sid:rev`, in its
Rule filter. The other filters and the layout stay as they were.

### Old alerts

At the bottom of the screen, folded: `GET /archive`, when it is opened.

```json
{"zips": [{"name": "alerts_2026-11-03_to_2026-11-12.zip", "first_day": "2026-11-03",
           "last_day": "2026-11-12", "bytes": 98304512}],
 "days": [{"name": "2026-11-13.jsonl.gz", "day": "2026-11-13", "bytes": 9437184}],
 "keep_days": 30, "zip_days": 10}
```

- The alerts that have left the database (see README.md, "Old alerts"):
  each 10-day zip, then the day files waiting for theirs, with their sizes,
  and how long the archive keeps them. Without an archive
  (`IDS_ALERT_ARCHIVE_DAYS=0`) both lists are empty and there are no
  `keep_days` and `zip_days`.
- `GET /archive/{name}` sends one of them as a download; the page fetches
  it with the token, then saves it. Any other name is 404, so nothing else
  on the machine can be asked for. A day file is still being added to, so a
  copy may end in the middle of a minute's alerts; those are in the next
  copy.

## Combined JSON export

### Download or send what the filters choose

"Download JSON" and "Send", at the end of the Show row, take the alerts
the filters choose; only the outcome of a click is written out, and the
buttons' hover text says what the file would hold (or why a button is off).
With "the newest 20" side by side the file holds each engine's newest 20,
in the combined layout the newest 20 of both together.

1. `GET /export/selection?<filters>` (every 10 seconds) gives what the file
   would hold: `{"alerts": {"snort": 20, "suricata": 20}, "total": 40,
   "first_ms": …, "last_ms": …, "complete_end_ms": …, "max_alerts": 150000}`.
   With both engines the alerts stop at the latest complete time
   (`complete_end_ms`; see the window end in docs/combined-json-format.md),
   so a packet both engines alerted on isn't shown as one engine's; one
   engine's alerts need no wait (`null`).
2. `GET /export/selection/file?<filters>` builds the file and returns it as
   the body, with `Content-Disposition` (such as
   `snort_suricata_combined_20261111_1630_last20each.json` or
   `snort_combined_20261111_1200_24hours.json`) and the same `X-…` headers
   as `/export`. Its window is the time range chosen, or with "newest N" or
   no range the alerts' own span; it holds only the alerts the filters
   choose, from the database. 404 when none match; 413 over `max_alerts`.
3. `POST /export/selection/send?<filters>` builds the same file and POSTs it
   to the LLM PC: to `IDS_LLM_URL` in .env (`http://` or `https://`), with
   `Content-Type: application/json`, `X-Filename`, the `X-…` counts, and
   `Authorization: Bearer <IDS_LLM_TOKEN>` when that is set. It answers
   `{"sent": true, "to": "192.168.50.20:8000", "filename": …, "bytes": …,
   "alerts": …, "packets": …, "both_engine_packets": …}`; 503 while
   `IDS_LLM_URL` is empty (`send_to` in `/options` is then `null` and the
   button is off), and 502 when the LLM PC can't be reached or answers
   other than 2xx (it waits up to 60 seconds).

### A whole time window

These endpoints build the file for every alert of a time window, whatever
the filters (the page no longer uses them):

1. `GET /export/window?length=15 minutes` gives `start_ms`, `end_ms` and
   `complete_end_ms`, for the screen to show. With `end_ms` the user's chosen
   end; a chosen end later than `complete_end_ms` is moved back to it
   (`moved_back: true`). It also gives `stored_alerts`, the window's alerts
   in the database, `max_alerts`, the most one export holds
   (`IDS_EXPORT_MAX_ALERTS`, 150,000), and `from_archive`, true when the
   window starts before the database's oldest alert, so its older alerts
   come from the archive. The screen says so, and won't build a window
   whose stored alerts are over `max_alerts`.
2. `GET /export` with the same `length` (and `end_ms`) builds the file for
   that window and returns it as the body (`application/json`, with
   `Content-Disposition: attachment; filename="snort_suricata_combined_20261103_1321_15min.json"`).
   Its window and counts come in headers, so the app can show them without
   reading the file: `X-Window-Start-Ms`, `X-Window-End-Ms`,
   `X-Alerts-Snort` (120), `X-Alerts-Suricata` (179), `X-Packets` (192),
   `X-Both-Engine-Packets` (86). With "Latest complete time" the window can
   move on by a few seconds between the two calls; the headers give the
   file's own. The app lets the user save or share the file. Its format is
   in `docs/combined-json-format.md`.

The window's alerts come from the database, and the ones that have left it
from the archive's day files and zips. A window with more than `max_alerts`
alerts is refused with 413 and `{"error": "This window holds 580,123
alerts; one export holds at most 150,000 on this machine. Choose a shorter
length."}` before anything is built: building takes about 8 KB of memory
an alert (1 hour of 3,574 alerts peaked at 94 MB, 6 hours of 21,032 at 227
MB), so 7 days at 83,000 alerts a day would need about 4.5 GB, more than
the VM has free. Building took 1.9 s for that hour and 8.3 s for those 6
hours; rule lookups are kept between exports while the server runs.

## Times

Show times in PKT (UTC+05:00), for example with
`new Date(ms).toLocaleString("en-GB", {timeZone: "Asia/Karachi"})`. The
dashboard writes the date only when it is not today.
