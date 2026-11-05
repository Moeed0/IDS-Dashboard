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
request. For development, `npm run dev` serves the page with live reload on
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
| `GET /alerts?engine=&range=&search=&page=&page_size=` | `alerts(db_path, …)` | One page of alerts, newest first |
| `GET /export/window?length=&end_ms=` | `export_window(db_path, length, end_ms)` | Start and end of a combined export |
| `GET /export?length=&end_ms=` | `combined_export(db_path, …)` | The combined JSON file for that window |

`/options` gives the fixed choices, so the app does not repeat them:

```json
{"engines": ["snort", "suricata"],
 "export_lengths": ["5 minutes", "10 minutes", "15 minutes", "…", "7 days"],
 "default_export_length": "15 minutes",
 "time_ranges": [{"label": "Last 24 hours", "ms": 86400000}, "…",
                 {"label": "All stored", "ms": null}],
 "page_sizes": [10, 25, 50, 100, 250],
 "chart_steps": [5, 10, 15], "default_chart_step": 15,
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
  "last_hour": {"start_ms": 1793691399000, "end_ms": 1793694999000,
                "alerts": {"snort": 483, "suricata": 758},
                "packets": 824, "both": 332, "snort_only": 93, "suricata_only": 399},
  "last_day": {"start_ms": 1793608200000, "end_ms": 1793694600000, "step_ms": 900000,
               "alerts": {"snort": [118, 121, "…96 counts"], "suricata": ["…"]}},
  "top_rules": {"length": "1 day", "start_ms": 1793608599000, "end_ms": 1793694999000,
                "rules": {"snort": [{"rule": "116:444", "gid": 116, "sid": 444, "rev": 1,
                                     "message": "(ipv4) IPv4 option set",
                                     "alerts": 6640}, "…up to 10"],
                          "suricata": ["…"]}}
}
```

What the screen shows:

- **Status**: a tile for each engine with a green dot while it runs (red
  when stopped, grey when that is not known; `running` from `/status`), how
  long ago its newest alert was and its `rules`. The tiles take these from
  `/status`, which comes every 10 seconds, and from `engines` until it has
  come; the "ago" times count on between answers, as in the status panel
  (below). What is stored and HOME_NET are in the status panel.
- **Warnings**: an engine with no `newest_ms`, or one more than 30 minutes
  old: "No Snort alert stored for 2 h. Check Snort and
  live_dual_collector.py." An engine with `unmatched_lab_attackers`: its
  EXTERNAL_NET keeps its rules from matching those lab attackers.
- **Last hour** (`null` when no alert is stored): tiles for alerts per
  engine, packets with alerts, packets both engines alerted on (with their
  share of the packets), and packets only one engine alerted on.
- **Last 24 hours** (`null` likewise): a line chart, one line per engine, of
  `alerts[engine][i]` at `start_ms + i * step_ms`; Snort `#3987e5`, Suricata
  `#d95926` on a dark background (`#2a78d6` and `#eb6834` on a light one).
  `step_minutes` (5, 10 or 15; 15 when left out) sets the time between the
  points; the page keeps the user's choice in that browser. The lines are
  named at their ends, with no legend. The chart is small while each
  engine's counts stay near their usual level and grows by itself when a
  burst rises above it: from twice the engine's median count to six times,
  it goes from its small to its full height.
- **Live**, the chart's fourth choice after 5, 10 and 15 minutes (also kept
  in that browser). See "Live chart" below.
- **Top rules** (`null` likewise): each engine's most frequent rules over the
  last `top_rules_length` (one of the export lengths, `1 day` when left out),
  as a list (GID, SID, revision, alerts, message); a rule that fired with two
  revisions has a row for each. `rule` is the SID with a GID other than 1
  first, as the combined export names rules.

The last hour, the last 24 hours and the top rules end at `complete_end_ms`,
the latest time up to which both engines' alerts are stored (one engine's can
be stored later than the other's); their packet counts match the combined
export's.

### Live chart

`GET /live`, every 5 seconds while the chart's Live choice is on:

```json
{"checked_ms": 1793862463000, "window_ms": 900000,
 "start_ms": 1793861550000, "step_ms": 30000,
 "alerts": {"snort": [3, 9, 1, "…"], "suricata": [4, 15, 2, "…"]}}
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
- **Labels:** the time is labelled every 2 minutes, and the heading says
  "Last 15 minutes".
- **Hover:** the hover box lists only the lines that reach that point.
- **Height:** it grows on a burst as the 24-hour chart does.

## Status panel

`GET /status`, every 10 seconds, for a panel down the right side of every
screen (above the screen on a narrow one):

```json
{"checked_ms": 1793792210825,
 "running": {"snort": true, "suricata": true, "collector": true},
 "collector_saved_ms": 1793792209007,
 "complete_end_ms": 1793792171000,
 "alert_retention": 200000,
 "engines": {"snort": {"…": "as on the Overview"}, "suricata": {"…": "…"}}}
```

`running` says whether Snort, Suricata and `live_dual_collector.py` run on
the IDS machine (from `/proc`; `null` when it cannot be read).
`collector_saved_ms` is when the collector last saved its place in the
engines' logs, which it does each time it stores alerts. `engines` is the
Overview's.

The panel shows at its top "Live"; "No new alerts" after 5 minutes without
one stored; "Partly working" when an engine is stopped; "Not updating" when
the collector is stopped or the latest `/status` request failed. Then the
collector with a green or red dot and how long ago it stored alerts; the
stored alerts (total, per engine, since when, how many are kept); and each
engine's HOME_NET. Snort and Suricata,
with their dots, are the Overview's first row. One `/status` request feeds
both.

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
  "total": 9924, "page": 1, "pages": 397, "page_size": 25,
  "rows": [
    {"id": 229839, "engine": "snort", "time_ms": 1793694999066, "rule": "112:1",
     "gid": 112, "sid": 1, "rev": 1,
     "message": "(arp_spoof) unicast ARP request", "class": null, "severity": 3,
     "protocol": "ARP", "service": null, "src": null, "dst": null}
  ]
}
```

- `engine` is `snort`, `suricata` or left out for both. The dashboard shows
  two lists side by side (one call per engine) or one combined list.
- `range` is one of the time range labels; the API counts it back from its
  own clock, which the stored times follow. `since_ms` (epoch ms) can be sent
  instead; left out, the list has every stored alert.
- `page` starts at 1; `page_size` is 1 to 250.
- `search` matches the message, the rule (`116:444`), the class, protocol,
  service, either endpoint (`192.168.50.1:53`) or the PKT time
  (`2026-11-03 12:40`), in any case. A page past the last returns the last
  page.
- `rule` is the SID, with the GID first when it is not 1 (what the search
  matches); `gid`, `sid` and `rev` are the rule's numbers (`rev` is `null`
  when the engine gave none). `severity` is 1
  (most severe) to 4. `src` and `dst` are `address:port`, `[IPv6]:port`, the
  address alone (no ports), or `null` (no IP addresses, such as ARP).
- Rows the dashboard shows: time, GID, SID, revision, severity, message
  (side by side); time, engine, GID, SID, revision, severity, protocol,
  source, destination, message (combined).

## Combined JSON export

1. `GET /export/window?length=15 minutes` gives `start_ms`, `end_ms` and
   `complete_end_ms`, for the screen to show. With `end_ms` the user's chosen
   end; a chosen end later than `complete_end_ms` is moved back to it
   (`moved_back: true`).
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

Building takes about 0.7 s for 15 minutes and 3–4 s for 24 hours on the live
data; rule lookups are kept between exports while the server runs.

## Times

Show times in PKT (UTC+05:00), for example with
`new Date(ms).toLocaleString("en-GB", {timeZone: "Asia/Karachi"})`. The
dashboard writes the date only when it is not today.
