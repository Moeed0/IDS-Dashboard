import json
import os
import sqlite3
import time
from datetime import datetime, timedelta

import pytest

from ids.combined_detections import PKT
from ids.dashboard_data import alerts, combined_export, export_window, live, overview, status


def _ms(*parts):
    return int(datetime(*parts, tzinfo=PKT).timestamp() * 1000)


def _database(path, alerts):
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE alerts (id INTEGER PRIMARY KEY, engine TEXT, "
        "event_ts_utc INTEGER, gid INTEGER, sid INTEGER, rev INTEGER, msg TEXT, "
        "classification TEXT, severity INTEGER, priority INTEGER, protocol TEXT, "
        "service TEXT, src_addr TEXT, src_port INTEGER, dst_addr TEXT, "
        "dst_port INTEGER, rule_key TEXT, raw_json TEXT)"
    )
    connection.executemany(
        "INSERT INTO alerts (engine, event_ts_utc, gid, sid, rev, msg, classification, "
        "severity, protocol, service, src_addr, src_port, dst_addr, dst_port, raw_json) "
        "VALUES (:engine, :time, :gid, :sid, :rev, :msg, :class, :severity, :protocol, "
        ":service, :src_addr, :src_port, :dst_addr, :dst_port, '{}')",
        [
            {
                "rev": 1, "class": None, "severity": 3, "protocol": None, "service": None,
                "src_addr": None, "src_port": None, "dst_addr": None, "dst_port": None,
                **alert,
            }
            for alert in alerts
        ],
    )
    connection.commit()
    connection.close()


def _alert(engine, time, gid, sid, msg, **fields):
    return {"engine": engine, "time": time, "gid": gid, "sid": sid, "msg": msg, **fields}


IPV4_OPTION = (116, 444, "(ipv4) IPv4 option set")
PADDING = (1, 2200007, "SURICATA IPv4 padding required ")


def _sources(tmp_path):
    """Snort and Suricata configured with EXTERNAL_NET outside HOME_NET."""
    snort = tmp_path / "snort.lua"
    snort.write_text("HOME_NET = '192.168.50.0/24'\nEXTERNAL_NET = '!$HOME_NET'\n")
    suricata = tmp_path / "suricata.yaml"
    suricata.write_text('    HOME_NET: "[192.168.50.0/24]"\n    EXTERNAL_NET: "any"\n')
    return {
        "snort": {"config_file": str(snort), "engine_rule_count": 48661},
        "suricata": {"config_file": str(suricata), "engine_rule_count": 68823},
    }


def test_overview_counts_end_where_both_engines_are_complete(tmp_path):
    db_path = tmp_path / "ids_live.db"
    _database(
        db_path,
        [
            _alert("snort", _ms(2026, 11, 2, 13, 0), 1, 51037, "POLICY-OTHER IGMP membership query attempt"),
            _alert("snort", _ms(2026, 11, 3, 13, 30), 1, 24301, "PROTOCOL-ICMP IPv6 MLD multicast listener query attempt"),
            _alert("snort", _ms(2026, 11, 3, 14, 0), *IPV4_OPTION),
            _alert("snort", _ms(2026, 11, 3, 14, 10), *IPV4_OPTION),
            # Snort's newest stored alert; Suricata's alerts after it wait
            # for Snort's next batch.
            _alert("snort", _ms(2026, 11, 3, 14, 20, 30, 500000), *IPV4_OPTION),
            _alert("suricata", _ms(2026, 11, 3, 13, 0), *PADDING),
            _alert("suricata", _ms(2026, 11, 3, 14, 5), *PADDING),
            _alert("suricata", _ms(2026, 11, 3, 14, 22, 10), 1, 2001119, "ET DNS Standard query response, Refused"),
        ],
    )

    data = overview(db_path, _sources(tmp_path), alert_retention=50000)

    end = _ms(2026, 11, 3, 14, 20, 30)
    assert data["complete_end_ms"] == end
    assert data["alert_retention"] == 50000
    # Every stored alert counts here. The lab attacker (config/lab_phases.json)
    # is inside HOME_NET, which Snort's EXTERNAL_NET leaves out.
    assert data["engines"] == {
        "snort": {
            "newest_ms": _ms(2026, 11, 3, 14, 20, 30, 500000),
            "alerts": 5,
            "oldest_ms": _ms(2026, 11, 2, 13, 0),
            "rules": 48661,
            "home_net": "192.168.50.0/24",
            "external_net": "!$HOME_NET",
            "unmatched_lab_attackers": ["192.168.50.141"],
        },
        "suricata": {
            "newest_ms": _ms(2026, 11, 3, 14, 22, 10),
            "alerts": 3,
            "oldest_ms": _ms(2026, 11, 3, 13, 0),
            "rules": 68823,
            "home_net": "[192.168.50.0/24]",
            "external_net": "any",
            "unmatched_lab_attackers": [],
        },
    }
    # The last hour ends where both engines are complete. Alerts without
    # addresses are never on one packet.
    assert data["last_hour"] == {
        "start_ms": end - 3_600_000,
        "end_ms": end,
        "alerts": {"snort": 3, "suricata": 1},
        "packets": 4,
        "both": 0,
        "snort_only": 3,
        "suricata_only": 1,
    }

    day = data["last_day"]
    # Whole 15-minute steps before the complete time.
    assert (day["start_ms"], day["end_ms"], day["step_ms"]) == (
        _ms(2026, 11, 2, 14, 15), _ms(2026, 11, 3, 14, 15), 900_000,
    )
    assert [len(day["alerts"][engine]) for engine in ("snort", "suricata")] == [96, 96]

    def busy(engine):
        start = datetime.fromtimestamp(day["start_ms"] / 1000, tz=PKT)
        return {
            f"{start + timedelta(minutes=15 * index):%H:%M}": count
            for index, count in enumerate(day["alerts"][engine])
            if count
        }

    assert busy("snort") == {"13:30": 1, "14:00": 2}
    assert busy("suricata") == {"13:00": 1, "14:00": 1}
    # The top rules cover the last day up to the complete time. A GID other
    # than 1 is kept in the rule's name too.
    assert data["top_rules"] == {
        "length": "1 day",
        "start_ms": end - 86_400_000,
        "end_ms": end,
        "rules": {
            "snort": [
                {
                    "rule": "116:444", "gid": 116, "sid": 444, "rev": 1,
                    "message": "(ipv4) IPv4 option set", "alerts": 2,
                },
                {
                    "rule": "24301", "gid": 1, "sid": 24301, "rev": 1,
                    "message": "PROTOCOL-ICMP IPv6 MLD multicast listener query attempt",
                    "alerts": 1,
                },
            ],
            "suricata": [
                {
                    "rule": "2200007", "gid": 1, "sid": 2200007, "rev": 1,
                    "message": "SURICATA IPv4 padding required", "alerts": 2,
                },
            ],
        },
    }
    # The screen's data is plain JSON.
    assert json.loads(json.dumps(data)) == data


def test_top_rules_list_each_revision_of_a_rule(tmp_path):
    db_path = tmp_path / "ids_live.db"
    mld = (1, 24301, "PROTOCOL-ICMP IPv6 MLD multicast listener query attempt")
    _database(
        db_path,
        [
            # The rule before and after a rule update.
            _alert("snort", _ms(2026, 11, 3, 13, 0), *mld, rev=4),
            _alert("snort", _ms(2026, 11, 3, 13, 30), *mld, rev=5),
            _alert("snort", _ms(2026, 11, 3, 13, 40), *mld, rev=5),
            _alert("snort", _ms(2026, 11, 3, 14, 20), *IPV4_OPTION),
            _alert("suricata", _ms(2026, 11, 3, 14, 30), *PADDING),
        ],
    )

    top = overview(db_path, {})["top_rules"]["rules"]["snort"]

    assert [(row["rule"], row["rev"], row["alerts"]) for row in top] == [
        ("24301", 5, 2), ("24301", 4, 1),
    ]


def test_chart_step_and_top_rules_window_can_be_chosen(tmp_path):
    db_path = tmp_path / "ids_live.db"
    mld = (1, 24301, "PROTOCOL-ICMP IPv6 MLD multicast listener query attempt")
    _database(
        db_path,
        [
            _alert("snort", _ms(2026, 11, 3, 13, 0), *mld, rev=4),
            _alert("snort", _ms(2026, 11, 3, 13, 30), *mld, rev=5),
            _alert("snort", _ms(2026, 11, 3, 13, 40), *mld, rev=5),
            _alert("snort", _ms(2026, 11, 3, 14, 20), *IPV4_OPTION),
            _alert("suricata", _ms(2026, 11, 3, 14, 30), *PADDING),
        ],
    )

    data = overview(db_path, {}, step_minutes=5, top_rules_length="1 hour")

    # Complete up to 14:19:59, the last whole second before Snort's newest.
    day = data["last_day"]
    assert (day["end_ms"], day["step_ms"], len(day["alerts"]["snort"])) == (
        _ms(2026, 11, 3, 14, 15), 300_000, 288,
    )
    assert sum(day["alerts"]["snort"]) == 3
    top = data["top_rules"]
    assert (top["length"], top["start_ms"], top["end_ms"]) == (
        "1 hour", _ms(2026, 11, 3, 13, 19, 59), _ms(2026, 11, 3, 14, 19, 59),
    )
    assert [(row["rule"], row["rev"], row["alerts"]) for row in top["rules"]["snort"]] == [
        ("24301", 5, 2),
    ]
    assert top["rules"]["suricata"] == []
    with pytest.raises(ValueError):
        overview(db_path, {}, step_minutes=7)
    with pytest.raises(ValueError):
        overview(db_path, {}, top_rules_length="2 hours")


def test_overview_of_an_empty_database(tmp_path):
    db_path = tmp_path / "ids_live.db"
    _database(db_path, [])

    data = overview(db_path, {})

    assert data["complete_end_ms"] is None
    assert data["last_hour"] is None
    assert data["last_day"] is None
    assert data["top_rules"] is None
    assert data["engines"]["snort"]["newest_ms"] is None
    assert data["engines"]["snort"]["alerts"] == 0


def _alert_list_database(tmp_path):
    db_path = tmp_path / "ids_live.db"
    _database(
        db_path,
        [
            _alert(
                "suricata", _ms(2026, 11, 3, 12, 38, 48), 1, 2001119,
                "ET DNS Standard query response, Refused",
                **{"class": "Not Suspicious Traffic", "protocol": "UDP", "service": "dns",
                   "src_addr": "192.168.50.1", "src_port": 53,
                   "dst_addr": "192.168.50.122", "dst_port": 50160},
            ),
            _alert(
                "snort", _ms(2026, 11, 3, 12, 39, 49), *IPV4_OPTION,
                **{"class": "none", "protocol": "IP", "service": "unknown",
                   "src_addr": "192.168.50.122", "dst_addr": "224.0.0.2"},
            ),
            _alert(
                "suricata", _ms(2026, 11, 3, 12, 40, 8), 1, 2030387,
                "ET EXPLOIT Possible CVE-2020-11899 Multicast out-of-bound read",
                **{"severity": 1, "protocol": "UDP",
                   "src_addr": "fe80:0000:0000:0000:2d37:6cf4:f5c8:64f7", "src_port": 5353,
                   "dst_addr": "ff02:0000:0000:0000:0000:0000:0000:00fb", "dst_port": 5353},
            ),
        ],
    )
    return db_path


def test_alert_list_pages_newest_first(tmp_path):
    db_path = _alert_list_database(tmp_path)

    first = alerts(db_path, page_size=2)
    second = alerts(db_path, page=2, page_size=2)

    assert (first["total"], first["page"], first["pages"]) == (3, 1, 2)
    assert [row["rule"] for row in first["rows"]] == ["2030387", "116:444"]
    assert [row["rule"] for row in second["rows"]] == ["2001119"]
    # A page past the last is the last page.
    assert alerts(db_path, page=9, page_size=2)["page"] == 2
    newest, snort = first["rows"]
    assert newest == {
        "id": 3,
        "engine": "suricata",
        "time_ms": _ms(2026, 11, 3, 12, 40, 8),
        "rule": "2030387",
        "gid": 1,
        "sid": 2030387,
        "rev": 1,
        "message": "ET EXPLOIT Possible CVE-2020-11899 Multicast out-of-bound read",
        "class": None,
        "severity": 1,
        "protocol": "UDP",
        "service": None,
        # IPv6 in its short form, with brackets before the port.
        "src": "[fe80::2d37:6cf4:f5c8:64f7]:5353",
        "dst": "[ff02::fb]:5353",
    }
    # "none" and "unknown" say nothing; an address without a port is alone.
    assert (snort["class"], snort["service"], snort["src"]) == (None, None, "192.168.50.122")


def test_alert_list_filters_by_engine_time_and_search(tmp_path):
    db_path = _alert_list_database(tmp_path)

    def rules(**query):
        return [row["rule"] for row in alerts(db_path, **query)["rows"]]

    assert rules(engine="snort") == ["116:444"]
    assert rules(since_ms=_ms(2026, 11, 3, 12, 39)) == ["2030387", "116:444"]
    # The search looks at the message, rule, class, endpoints and PKT time,
    # in any case.
    assert rules(search="refused") == ["2001119"]
    assert rules(search="116:444") == ["116:444"]
    # The rule as the screens show it, gid:sid:rev.
    assert rules(search="1:2001119:1") == ["2001119"]
    assert rules(search="not suspicious") == ["2001119"]
    assert rules(search="192.168.50.1:53") == ["2001119"]
    assert rules(search="12:40:08") == ["2030387"]
    assert rules(search="100%") == []
    assert alerts(db_path, search="nothing like this")["pages"] == 1


def test_alert_search_finds_a_rule_without_a_revision(tmp_path):
    db_path = tmp_path / "ids_live.db"
    _database(db_path, [_alert("snort", _ms(2026, 11, 3, 12, 39), *IPV4_OPTION, rev=None)])

    assert [row["rule"] for row in alerts(db_path, search="116:444")["rows"]] == ["116:444"]


def _proc(tmp_path, processes):
    """A /proc with these command lines."""
    proc = tmp_path / "proc"
    for pid, arguments in processes.items():
        (proc / pid).mkdir(parents=True)
        (proc / pid / "cmdline").write_bytes(b"\0".join(arguments) + b"\0")
    # Not a process.
    (proc / "self").mkdir(parents=True, exist_ok=True)
    return proc


def test_status_shows_what_runs_and_when_the_collector_last_stored(tmp_path):
    db_path = _alert_list_database(tmp_path)
    state_file = tmp_path / "ids_collector_state.json"
    state_file.write_text("{}")
    os.utime(state_file, (1793789000, 1793789000))
    proc = _proc(tmp_path, {
        "5762": [b"/usr/local/bin/snort", b"-c", b"/usr/local/etc/snort/snort.lua", b"-i", b"ens38"],
        "5822": [b"/usr/bin/suricata", b"-D", b"--af-packet"],
        "10543": [b".venv/bin/python", b"src/live_dual_collector.py"],
    })

    data = status(db_path, state_file, _sources(tmp_path), alert_retention=50000, proc_dir=proc)

    assert data["running"] == {"snort": True, "suricata": True, "collector": True}
    assert data["collector_saved_ms"] == 1793789000000
    # One second before Snort's newest alert, as on the Overview.
    assert data["complete_end_ms"] == _ms(2026, 11, 3, 12, 39, 48)
    assert data["alert_retention"] == 50000
    # The engines as the Overview has them.
    assert data["engines"]["snort"] == {
        "newest_ms": _ms(2026, 11, 3, 12, 39, 49),
        "alerts": 1,
        "oldest_ms": _ms(2026, 11, 3, 12, 39, 49),
        "rules": 48661,
        "home_net": "192.168.50.0/24",
        "external_net": "!$HOME_NET",
        "unmatched_lab_attackers": ["192.168.50.141"],
    }
    assert data["engines"] == overview(db_path, _sources(tmp_path))["engines"]
    assert abs(data["checked_ms"] - time.time() * 1000) < 60_000
    assert json.loads(json.dumps(data)) == data


def test_status_when_parts_are_stopped(tmp_path):
    db_path = _alert_list_database(tmp_path)
    # A command that only names the collector's file is not the collector.
    proc = _proc(tmp_path, {"7": [b"grep", b"live_dual_collector.py"], "8": [b""]})

    data = status(db_path, tmp_path / "no_state.json", proc_dir=proc)

    assert data["running"] == {"snort": False, "suricata": False, "collector": False}
    assert data["collector_saved_ms"] is None
    # No /proc to read: not known.
    assert status(db_path, None, proc_dir=tmp_path / "missing")["running"] is None


def test_live_chart_moves_with_the_clock_and_each_line_ends_where_its_engine_is_stored(tmp_path):
    db_path = tmp_path / "ids_live.db"
    _database(
        db_path,
        [
            _alert("suricata", _ms(2026, 11, 5, 11, 45, 10), *PADDING),
            _alert("suricata", _ms(2026, 11, 5, 11, 45, 40), *PADDING),
            _alert("snort", _ms(2026, 11, 5, 11, 50, 10), *IPV4_OPTION),
            _alert("snort", _ms(2026, 11, 5, 11, 58, 5), *IPV4_OPTION),
            _alert("suricata", _ms(2026, 11, 5, 12, 0, 5), *PADDING),
            _alert("suricata", _ms(2026, 11, 5, 12, 0, 31), *PADDING),
        ],
    )

    data = live(db_path, now=datetime(2026, 11, 5, 12, 0, 45, tzinfo=PKT))

    # The last 15 minutes in whole half minutes, from the one that starts
    # before them.
    assert (data["checked_ms"], data["window_ms"], data["start_ms"], data["step_ms"]) == (
        _ms(2026, 11, 5, 12, 0, 45), 900_000, _ms(2026, 11, 5, 11, 45, 30), 30_000,
    )
    # Snort's alerts are stored up to its newest one, in the 11:58:00 step,
    # so its counts end before that step; Suricata's run up to 12:00:30.
    snort, suricata = data["alerts"]["snort"], data["alerts"]["suricata"]
    assert (len(snort), len(suricata)) == (25, 30)
    assert [index for index, value in enumerate(snort) if value] == [9]
    assert [index for index, value in enumerate(suricata) if value] == [0, 29]
    assert json.loads(json.dumps(data)) == data
    # Ten seconds on, the same steps have the same counts.
    later = live(db_path, now=datetime(2026, 11, 5, 12, 0, 55, tzinfo=PKT))
    assert (later["start_ms"], later["alerts"]) == (data["start_ms"], data["alerts"])


def test_live_chart_without_recent_alerts(tmp_path):
    now = datetime(2026, 11, 5, 12, 0, 45, tzinfo=PKT)
    # Alerts from 3 November only, then none at all: no line in view.
    assert live(_alert_list_database(tmp_path), now=now)["alerts"] == {"snort": [], "suricata": []}
    db_path = tmp_path / "empty.db"
    _database(db_path, [])
    assert live(db_path, now=now)["alerts"] == {"snort": [], "suricata": []}


def test_export_window_ends_at_the_latest_complete_time(tmp_path):
    db_path = _alert_list_database(tmp_path)
    complete = _ms(2026, 11, 3, 12, 39, 48)

    window = export_window(db_path, "15 minutes")
    chosen = export_window(db_path, "5 minutes", _ms(2026, 11, 3, 12, 30))
    later = export_window(db_path, "5 minutes", _ms(2026, 11, 3, 13, 0))

    assert window == {
        "start_ms": complete - 900_000, "end_ms": complete,
        "complete_end_ms": complete, "moved_back": False,
    }
    assert (chosen["start_ms"], chosen["end_ms"], chosen["moved_back"]) == (
        _ms(2026, 11, 3, 12, 25), _ms(2026, 11, 3, 12, 30), False,
    )
    assert (later["end_ms"], later["moved_back"]) == (complete, True)
    empty = tmp_path / "empty.db"
    _database(empty, [])
    assert export_window(empty, "15 minutes") is None


def test_combined_export_gives_the_file_and_its_counts(tmp_path):
    db_path = _alert_list_database(tmp_path)

    built = combined_export(
        db_path, _ms(2026, 11, 3, 12, 30), _ms(2026, 11, 3, 12, 45), "15 minutes",
        rule_intelligence=None,
    )

    assert built["filename"] == "snort_suricata_combined_20261103_1230_15min.json"
    assert built["alerts"] == {"snort": 1, "suricata": 2}
    assert (built["packets"], built["both_engine_packets"]) == (3, 0)
    assert json.loads(built["json"])["alerts"] == built["alerts"]


def test_a_machine_running_one_engine_shows_only_that_engine(tmp_path):
    """IDS_ENGINES=suricata: Snort's alerts stored before neither show nor
    hold the latest complete time back at Snort's newest alert."""
    db_path = _alert_list_database(tmp_path)
    proc = _proc(tmp_path, {
        "5822": [b"/usr/bin/suricata", b"-D", b"--af-packet"],
        "10543": [b".venv/bin/python", b"src/live_dual_collector.py"],
    })
    sources = {"suricata": _sources(tmp_path)["suricata"]}
    only = ("suricata",)

    data = overview(db_path, sources, engines=only)
    state = status(db_path, None, sources, proc_dir=proc, engines=only)
    chart = live(db_path, now=datetime(2026, 11, 3, 12, 45, tzinfo=PKT), engines=only)
    window = export_window(db_path, "1 hour", engines=only)
    listed = alerts(db_path, engines=only)
    exported = combined_export(
        db_path, window["start_ms"], window["end_ms"], "1 hour", rule_intelligence=None,
        engines=only,
    )

    # One second before Suricata's newest alert (12:40:08), not Snort's (12:39:49).
    complete = _ms(2026, 11, 3, 12, 40, 7)
    assert data["complete_end_ms"] == state["complete_end_ms"] == window["end_ms"] == complete
    assert list(data["engines"]) == list(state["engines"]) == ["suricata"]
    assert list(data["last_day"]["alerts"]) == list(data["top_rules"]["rules"]) == ["suricata"]
    # The last hour ends there too, so it has one of Suricata's two alerts.
    assert data["last_hour"]["alerts"] == {"suricata": 1}
    assert (data["last_hour"]["packets"], data["last_hour"]["snort_only"]) == (1, 0)
    assert list(chart["alerts"]) == ["suricata"]
    assert state["running"] == {"suricata": True, "collector": True}
    assert listed["total"] == 2
    assert {row["engine"] for row in listed["rows"]} == {"suricata"}
    assert exported["alerts"] == {"suricata": 1}
