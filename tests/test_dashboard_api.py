import asyncio
import json
import re
import sqlite3
import stat
import time
import urllib.error
from datetime import datetime
from urllib.parse import urlencode

import pytest

from dashboard_api import create_app, new_token, save_new_token
from ids.combined_detections import PKT
from ids.uids import assign_uids
from ids.config import api_token_required
from ids.dashboard_data import alerts, overview

TOKEN = "test-token"


def _ms(*parts):
    return int(datetime(*parts, tzinfo=PKT).timestamp() * 1000)


def _database(path, rows):
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE alerts (id INTEGER PRIMARY KEY, engine TEXT, "
        "event_ts_utc INTEGER, gid INTEGER, sid INTEGER, rev INTEGER, msg TEXT, "
        "classification TEXT, severity INTEGER, priority INTEGER, protocol TEXT, "
        "service TEXT, src_addr TEXT, src_port INTEGER, dst_addr TEXT, "
        "dst_port INTEGER, rule_key TEXT, raw_json TEXT, uid INTEGER, app TEXT)"
    )
    connection.executemany(
        "INSERT INTO alerts (engine, event_ts_utc, gid, sid, msg, severity, raw_json) "
        "VALUES (?, ?, ?, ?, ?, 3, '{}')",
        rows,
    )
    # Each alert's UID, as the collector gives it.
    assign_uids(connection)
    connection.commit()
    connection.close()


ROWS = [
    ("suricata", _ms(2026, 11, 3, 12, 38, 48), 1, 2001119, "ET DNS Standard query response, Refused"),
    ("snort", _ms(2026, 11, 3, 12, 39, 49), 116, 444, "(ipv4) IPv4 option set"),
    ("suricata", _ms(2026, 11, 3, 12, 40, 8), 1, 2200007, "SURICATA IPv4 padding required"),
]


@pytest.fixture
def db_path(tmp_path):
    path = tmp_path / "ids_live.db"
    _database(path, ROWS)
    return path


def _app(db_path, web_dist=None):
    return create_app(
        db_path=db_path, ids_sources={}, token=TOKEN, rule_intelligence=None, web_dist=web_dist,
    )


def _get(app, path, /, token=TOKEN, method="GET", **query):
    """One request (GET unless ``method`` says) through the ASGI app:
    status, headers and body."""
    headers = [(b"host", b"testserver")]
    if token:
        headers.append((b"authorization", f"Bearer {token}".encode()))
    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "method": method, "scheme": "http", "path": path, "raw_path": path.encode(),
        "query_string": urlencode(query).encode(), "root_path": "",
        "headers": headers, "client": ("127.0.0.1", 50000), "server": ("testserver", 80),
    }
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    asyncio.run(app(scope, receive, send))
    start = next(message for message in sent if message["type"] == "http.response.start")
    body = b"".join(message.get("body", b"") for message in sent if message["type"] == "http.response.body")
    return (
        start["status"],
        {name.decode().lower(): value.decode() for name, value in start["headers"]},
        body,
    )


def test_every_endpoint_but_health_needs_the_token(db_path):
    app = _app(db_path)

    assert _get(app, "/health", token=None)[0] == 200
    for path in (
        "/options", "/overview", "/status", "/live", "/alerts", "/rule-pairs", "/export/window", "/export",
        "/alerts/values", "/export/selection", "/export/selection/file",
    ):
        status, headers, body = _get(app, path, token=None)
        assert (status, json.loads(body)) == (401, {"error": "missing or wrong token"})
        assert headers["www-authenticate"] == "Bearer"
        assert _get(app, path, token="wrong")[0] == 401
    assert _get(app, "/export/selection/send", token=None, method="POST")[0] == 401
    with pytest.raises(ValueError):
        create_app(db_path=db_path, ids_sources={}, token="")


def test_the_token_can_be_switched_off_for_testing(db_path, monkeypatch):
    # The process environment wins over .env.
    for value, required in (("false", False), ("Off", False), ("0", False), ("true", True)):
        monkeypatch.setenv("IDS_API_REQUIRE_TOKEN", value)
        assert api_token_required() is required

    app = create_app(
        db_path=db_path, ids_sources={}, token=None, rule_intelligence=None, web_dist=None,
    )

    for path in ("/options", "/overview", "/status", "/live", "/alerts", "/rule-pairs", "/export/window"):
        assert _get(app, path, token=None)[0] == 200
    # A browser that still sends an old token gets in too.
    assert _get(app, "/overview", token="old-token")[0] == 200


def test_the_screens_get_what_the_data_functions_return(db_path):
    app = _app(db_path)

    status, _, body = _get(app, "/overview")
    assert status == 200
    assert json.loads(body) == overview(db_path, {})
    status, _, body = _get(app, "/overview", step_minutes="5", top_rules_length="10 minutes")
    assert status == 200
    assert json.loads(body) == overview(
        db_path, {}, step_minutes=5, top_rules_length="10 minutes",
    )

    status, _, body = _get(app, "/alerts", engine="suricata", page_size="1", page="2")
    assert status == 200
    assert json.loads(body) == alerts(db_path, engine="suricata", page=2, page_size=1)

    options = json.loads(_get(app, "/options")[2])
    assert options["default_export_length"] in options["export_lengths"]
    assert {"label": "All stored", "ms": None} in options["time_ranges"]
    assert (options["chart_steps"], options["default_chart_step"]) == ([5, 10, 15], 15)
    assert options["live_step_seconds"] == 30
    assert options["default_top_rules_length"] in options["export_lengths"]


def test_overview_parameters_are_checked(db_path):
    app = _app(db_path)

    def error(**query):
        status, _, body = _get(app, "/overview", **query)
        assert status == 400
        return json.loads(body)["error"]

    assert error(step_minutes="7") == "step_minutes must be one of: 5, 10, 15"
    assert error(step_minutes="five") == "step_minutes must be a whole number"
    assert error(top_rules_length="2 hours").startswith(
        "top_rules_length must be one of: 5 minutes, 10 minutes, 15 minutes,"
    )


def test_the_status_says_what_runs_and_when_alerts_were_stored(db_path, tmp_path):
    state_file = tmp_path / "ids_collector_state.json"
    state_file.write_text("{}")
    app = create_app(
        db_path=db_path, ids_sources={}, token=TOKEN, state_file=state_file,
        rule_intelligence=None, web_dist=None,
    )

    status, _, body = _get(app, "/status")

    assert status == 200
    data = json.loads(body)
    assert set(data) == {
        "checked_ms", "running", "collector_saved_ms", "complete_end_ms", "alert_retention",
        "engines", "capture", "storage", "test_alert",
    }
    # No statistics files given.
    assert data["capture"] == {}
    assert data["collector_saved_ms"] == int(state_file.stat().st_mtime * 1000)
    assert data["engines"] == overview(db_path, {})["engines"]


def test_the_live_chart_ends_now(db_path):
    status, _, body = _get(_app(db_path), "/live")

    assert status == 200
    data = json.loads(body)
    assert set(data) == {"checked_ms", "window_ms", "start_ms", "step_ms", "alerts", "off"}
    assert data["off"] == []
    assert abs(data["checked_ms"] - time.time() * 1000) < 60_000
    assert (data["window_ms"], data["step_ms"]) == (900_000, 30_000)
    assert data["start_ms"] <= data["checked_ms"] - data["window_ms"]
    assert set(data["alerts"]) == {"snort", "suricata"}


def test_alert_list_parameters_are_checked(db_path):
    app = _app(db_path)

    def error(**query):
        status, _, body = _get(app, "/alerts", **query)
        assert status == 400
        return json.loads(body)["error"]

    assert error(engine="zeek") == "engine must be one of: snort, suricata"
    assert error(page="two") == "page must be a whole number"
    assert error(page_size="1000") == "page_size must be from 1 to 250"
    assert error(range="Last week") == (
        "range must be one of: Last 5 minutes, Last 10 minutes, Last 15 minutes, "
        "Last 30 minutes, Last hour, Last 24 hours, Last 7 days, Last 30 days, All stored"
    )
    assert error(severity="5") == "severity must be numbers from 1 to 4, like 1,2"
    assert error(rule="ET 1") == "rule must be a SID, GID:SID or GID:SID:Rev, like 2001119 or 116:444"
    assert error(source="router") == (
        "source must be an address or a network, like 192.168.50.122, 192.168.50.0/24 or 192.168.50."
    )
    assert error(last="0") == "last must be from 1 to 150000"
    assert error(port="70000") == "port must be from 0 to 65535"
    assert error(label="attacks") == "label must be attack or background"
    assert error(range="All stored", since_ms="1") == "give range or since_ms, not both"
    rows = json.loads(_get(app, "/alerts", range="All stored", search="padding")[2])["rows"]
    assert [row["rule"] for row in rows] == ["2200007"]


def test_export_gives_the_file_with_its_window_and_counts(db_path, tmp_path):
    app = _app(db_path)

    status, _, body = _get(app, "/export/window", length="5 minutes")
    window = json.loads(body)
    assert status == 200
    # Snort's newest alert at 12:39:49 sets the latest complete time.
    assert (window["end_ms"], window["moved_back"]) == (_ms(2026, 11, 3, 12, 39, 48), False)

    status, headers, body = _get(app, "/export", length="5 minutes")
    assert status == 200
    assert headers["content-type"] == "application/json"
    assert headers["content-disposition"] == (
        'attachment; filename="snort_suricata_combined_20261103_1234_5min.json"'
    )
    assert (headers["x-window-start-ms"], headers["x-window-end-ms"]) == (
        str(window["start_ms"]), str(window["end_ms"]),
    )
    assert (headers["x-alerts-snort"], headers["x-alerts-suricata"]) == ("0", "1")
    assert (headers["x-packets"], headers["x-both-engine-packets"]) == ("1", "0")
    assert json.loads(body)["alerts"] == {"suricata": 1}
    assert _get(app, "/export", length="2 hours")[0] == 400

    empty = tmp_path / "empty.db"
    _database(empty, [])
    status, _, body = _get(_app(empty), "/export/window")
    assert (status, json.loads(body)) == (404, {"error": "no alerts stored yet"})


def test_a_missing_database_is_reported(tmp_path):
    status, _, body = _get(_app(tmp_path / "missing.db"), "/overview")

    assert status == 503
    assert json.loads(body)["error"].startswith("could not read the live database")


def test_the_built_react_page_is_served_at_the_root(db_path, tmp_path):
    web_dist = tmp_path / "dist"
    (web_dist / "assets").mkdir(parents=True)
    (web_dist / "index.html").write_text("<!doctype html><div id=root></div>", encoding="utf-8")
    (web_dist / "assets" / "index.js").write_text("console.log(1)", encoding="utf-8")
    app = _app(db_path, web_dist)

    # The page and its files need no token: the page asks for it.
    status, headers, body = _get(app, "/", token=None)
    assert (status, headers["content-type"].split(";")[0]) == (200, "text/html")
    assert b"id=root" in body
    # Browsers check the page again on every visit, so a new build shows at
    # once; its scripts get a new name each build, so they can be kept.
    assert headers["cache-control"] == "no-cache"
    status, headers, _ = _get(app, "/assets/index.js", token=None)
    assert status == 200 and "cache-control" not in headers
    assert _get(app, "/missing.js", token=None)[0] == 404
    # The API's own paths still answer first, and still ask for the token.
    assert _get(app, "/overview", token=None)[0] == 401
    assert json.loads(_get(app, "/health", token=None)[2]) == {"ok": True}


def test_without_a_built_page_the_root_is_not_found(db_path, tmp_path):
    assert _get(_app(db_path, tmp_path / "no-build"), "/", token=None)[0] == 404


def test_new_tokens_are_short_and_easy_to_type():
    tokens = {new_token() for _ in range(50)}

    assert len(tokens) == 50
    # Four groups of four letters and digits, without i, l, o or u, which
    # can be taken for 1, 0 or v.
    letter = "[0-9a-hjkmnp-tv-z]"
    assert all(re.fullmatch(f"({letter}{{4}}-){{3}}{letter}{{4}}", token) for token in tokens)


def test_a_new_token_takes_the_old_ones_place_in_env(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "IDS_DB_FILE=ids_live.db\nIDS_API_TOKEN=old\n# A note\nexport IDS_API_TOKEN = older\n",
        encoding="utf-8",
    )

    token = save_new_token(env_file)

    # The other lines stay; only one token line is left, so it is the one read.
    assert env_file.read_text(encoding="utf-8") == (
        f"IDS_DB_FILE=ids_live.db\nIDS_API_TOKEN={token}\n# A note\n"
    )
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
    assert not (tmp_path / ".env.new").exists()

    without = tmp_path / "without.env"
    without.write_text("IDS_DB_FILE=ids_live.db", encoding="utf-8")
    added = save_new_token(without)
    assert without.read_text(encoding="utf-8") == f"IDS_DB_FILE=ids_live.db\nIDS_API_TOKEN={added}\n"
    missing = tmp_path / "missing.env"
    created = save_new_token(missing)
    assert missing.read_text(encoding="utf-8") == f"IDS_API_TOKEN={created}\n"


def test_a_machine_running_one_engine_offers_only_that_engine(db_path):
    app = create_app(
        db_path=db_path, ids_sources={}, token=TOKEN, rule_intelligence=None, web_dist=None,
        engines=("suricata",),
    )

    def get(path, **query):
        status, _, body = _get(app, path, **query)
        return status, json.loads(body)

    assert get("/options")[1]["engines"] == ["suricata"]
    assert list(get("/overview")[1]["engines"]) == ["suricata"]
    assert list(get("/status")[1]["engines"]) == ["suricata"]
    assert list(get("/live")[1]["alerts"]) == ["suricata"]
    assert get("/rule-pairs")[1]["pairs"] == []
    assert get("/alerts", engine="snort") == (400, {"error": "engine must be one of: suricata"})
    assert get("/alerts", range="All stored")[1]["total"] == 2
    # One second before Suricata's newest alert, not Snort's.
    assert get("/export/window", length="1 hour")[1]["end_ms"] == _ms(2026, 11, 3, 12, 40, 7)


def test_the_archive_is_listed_and_only_its_files_downloaded(db_path, tmp_path):
    archive = tmp_path / "archive"
    (archive / "days").mkdir(parents=True)
    (archive / "alerts_2026-11-03_to_2026-11-12.zip").write_bytes(b"zip bytes")
    (archive / "days" / "2026-11-13.jsonl.gz").write_bytes(b"gz bytes")
    (archive / "secret.txt").write_text("not for download")
    app = create_app(
        db_path=db_path, ids_sources={}, token=TOKEN, rule_intelligence=None, web_dist=None,
        archive_dir=archive, archive_settings={"keep_days": 30, "zip_days": 10},
    )

    status, _, body = _get(app, "/archive")
    assert status == 200
    assert json.loads(body) == {
        "zips": [{
            "name": "alerts_2026-11-03_to_2026-11-12.zip", "first_day": "2026-11-03",
            "last_day": "2026-11-12", "bytes": 9,
        }],
        "days": [{"name": "2026-11-13.jsonl.gz", "day": "2026-11-13", "bytes": 8}],
        "keep_days": 30,
        "zip_days": 10,
    }

    status, headers, body = _get(app, "/archive/alerts_2026-11-03_to_2026-11-12.zip")
    assert (status, body) == (200, b"zip bytes")
    assert 'filename="alerts_2026-11-03_to_2026-11-12.zip"' in headers["content-disposition"]
    assert _get(app, "/archive/2026-11-13.jsonl.gz")[2] == b"gz bytes"
    for path in ("/archive/secret.txt", "/archive/..%2Fsecret.txt", "/archive/../secret.txt",
                 "/archive/2026-11-12.jsonl.gz"):
        assert _get(app, path)[0] == 404
    assert _get(app, "/archive", token=None)[0] == 401
    # Without an archive (0 archive days), nothing is listed.
    assert json.loads(_get(_app(db_path), "/archive")[2]) == {"zips": [], "days": []}


def test_an_export_over_its_limit_is_refused_with_why(tmp_path):
    db_path = tmp_path / "ids_live.db"
    _database(db_path, [
        ("suricata", _ms(2026, 11, 3, 12, 38, 0), 1, 2200007, "SURICATA IPv4 padding required"),
        ("suricata", _ms(2026, 11, 3, 12, 38, 30), 1, 2200007, "SURICATA IPv4 padding required"),
        # The newest alerts, which set the latest complete time at 12:40:59.
        ("suricata", _ms(2026, 11, 3, 12, 41, 0), 1, 2200007, "SURICATA IPv4 padding required"),
        ("snort", _ms(2026, 11, 3, 12, 41, 30), 116, 444, "(ipv4) IPv4 option set"),
    ])
    app = create_app(
        db_path=db_path, ids_sources={}, token=TOKEN, rule_intelligence=None, web_dist=None,
        export_max_alerts=1,
    )

    window = json.loads(_get(app, "/export/window", length="30 minutes")[2])
    status, _, body = _get(app, "/export", length="30 minutes")

    assert (window["stored_alerts"], window["max_alerts"]) == (2, 1)
    assert status == 413
    assert json.loads(body)["error"].startswith("This window holds 2 alerts; one export holds at most 1")


def test_the_charts_show_when_the_machine_was_off(db_path):
    off = [(_ms(2026, 11, 3, 12, 0), _ms(2026, 11, 3, 12, 30))]
    reads = []

    def off_periods():
        reads.append(1)
        return off

    app = create_app(
        db_path=db_path, ids_sources={}, token=TOKEN, rule_intelligence=None, web_dist=None,
        off_periods=off_periods,
    )

    day = json.loads(_get(app, "/overview")[2])["last_day"]
    _get(app, "/overview")

    assert day["off"] == [[_ms(2026, 11, 3, 12, 0), _ms(2026, 11, 3, 12, 30)]]
    # The past boots are read once.
    assert reads == [1]


def test_a_damaged_database_says_how_to_restore(tmp_path):
    damaged = tmp_path / "damaged.db"
    damaged.write_bytes(b"not a database at all" * 100)

    status, _, body = _get(_app(damaged), "/overview")

    assert status == 503
    assert "scripts/restore_backup.py" in json.loads(body)["error"]
    # A missing file isn't damage.
    assert "restore" not in json.loads(_get(_app(tmp_path / "missing.db"), "/overview")[2])["error"]


def test_the_alert_list_takes_every_filter(db_path):
    app = _app(db_path)

    def rules(**query):
        status, _, body = _get(app, "/alerts", **query)
        assert status == 200
        return [row["rule"] for row in json.loads(body)["rows"]]

    assert rules(rule="116:444") == ["116:444"]
    assert rules(severity="3,4") == ["2200007", "116:444", "2001119"]
    assert rules(severity="1") == []
    # No stored alert has an app here; the filter is taken.
    assert rules(app="IGMP") == []
    assert rules(last="2") == ["2200007", "116:444"]
    assert rules(until_ms=str(_ms(2026, 11, 3, 12, 39))) == ["2001119"]
    page = json.loads(_get(app, "/alerts", last="2", page_size="1")[2])
    assert (page["total"], page["matching"], page["pages"]) == (2, 3, 2)
    status, _, body = _get(app, "/alerts/values")
    assert (status, json.loads(body)) == (200, {"protocols": [], "classes": [], "services": [], "apps": []})
    # One alert, for the side panel.
    status, _, body = _get(app, "/alerts/2")
    detail = json.loads(body)
    assert (status, detail["alert"]["rule"], detail["same_packet"]) == (200, "116:444", [])
    assert len(detail["packets"]) == 1
    status, _, body = _get(app, "/alerts/99")
    assert (status, json.loads(body)) == (404, {"error": "no such alert"})


def test_the_filtered_download_and_what_it_would_hold(db_path):
    app = _app(db_path)

    status, _, body = _get(app, "/export/selection", engine="suricata", last="1")
    assert (status, json.loads(body)) == (200, {
        "alerts": {"suricata": 1}, "total": 1,
        "first_ms": _ms(2026, 11, 3, 12, 40, 8), "last_ms": _ms(2026, 11, 3, 12, 40, 8),
        "complete_end_ms": None, "max_alerts": 150_000,
    })

    status, headers, body = _get(app, "/export/selection/file", engine="suricata", last="1")
    assert status == 200
    assert headers["content-disposition"] == (
        'attachment; filename="suricata_combined_20261103_1240_last1.json"'
    )
    assert (headers["x-alerts-snort"], headers["x-alerts-suricata"]) == ("0", "1")
    assert json.loads(body)["alerts"] == {"suricata": 1}
    status, _, body = _get(app, "/export/selection/file", severity="1")
    assert (status, json.loads(body)) == (404, {"error": "no alerts match the filters"})


def _sending_app(db_path, sender, url="http://192.168.50.20:8000/ids"):
    return create_app(
        db_path=db_path, ids_sources={}, token=TOKEN, rule_intelligence=None, web_dist=None,
        send_url=url, send_token="llm-token", sender=sender,
    )


def test_send_posts_the_chosen_alerts_to_the_llm_pc(db_path):
    sent = []

    def sender(url, body, headers):
        sent.append((url, json.loads(body), dict(headers)))
        return 200, "taken"

    app = _sending_app(db_path, sender)

    assert json.loads(_get(app, "/options")[2])["send_to"] == "192.168.50.20:8000"
    status, _, body = _get(app, "/export/selection/send", method="POST", engine="suricata", last="1")
    answer = json.loads(body)
    assert status == 200
    assert answer == {
        "sent": True, "to": "192.168.50.20:8000",
        "filename": "suricata_combined_20261103_1240_last1.json", "bytes": answer["bytes"],
        "alerts": {"suricata": 1}, "packets": 1, "both_engine_packets": 0,
    }
    [(url, document, headers)] = sent
    assert url == "http://192.168.50.20:8000/ids"
    assert document["alerts"] == {"suricata": 1}
    assert headers["Authorization"] == "Bearer llm-token"
    assert headers["X-Filename"] == answer["filename"]
    assert headers["Content-Type"] == "application/json; charset=utf-8"
    # Only a POST sends.
    assert _get(app, "/export/selection/send", engine="suricata")[0] == 405
    assert len(sent) == 1


def test_send_says_why_nothing_was_sent(db_path):
    off = _app(db_path)
    assert json.loads(_get(off, "/options")[2])["send_to"] is None
    status, _, body = _get(off, "/export/selection/send", method="POST")
    assert (status, json.loads(body)["error"]) == (
        503,
        "Send is off: put the LLM PC's address in IDS_LLM_URL in .env and restart the dashboard",
    )

    def unreachable(url, body, headers):
        raise urllib.error.URLError(ConnectionRefusedError(111, "Connection refused"))

    status, _, body = _get(
        _sending_app(db_path, unreachable, "http://llm-pc:8000/"), "/export/selection/send",
        method="POST", engine="suricata",
    )
    assert status == 502
    assert json.loads(body)["error"].startswith("could not reach the LLM PC at llm-pc:8000:")

    status, _, body = _get(
        _sending_app(db_path, lambda url, body, headers: (500, "model not loaded\n")),
        "/export/selection/send", method="POST", engine="suricata",
    )
    assert (status, json.loads(body)["error"]) == (
        502, "the LLM PC at 192.168.50.20:8000 answered 500: model not loaded",
    )
