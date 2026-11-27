from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from ids.rules_off import listing, rules, set_rule

APPLIER = Path(__file__).resolve().parents[1] / "deploy" / "rules-off" / "ids-rules-off.py"


def _applier():
    spec = importlib.util.spec_from_file_location("ids_rules_off", APPLIER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_dashboard_ticks_and_unticks_rules(tmp_path):
    path = tmp_path / ".runtime" / "rules_off.json"
    assert rules(path) == []

    set_rule(path, "suricata", "1", "2002752", True, message="ET INFO Reserved Internal IP Traffic", now_ms=5)
    set_rule(path, "snort", 129, 14, True, message="(stream_tcp) TCP timestamp is missing", now_ms=6)
    # Ticked again: once, the newest.
    set_rule(path, "snort", 129, 14, True, message="(stream_tcp) TCP timestamp is missing", now_ms=7)
    assert [(rule["engine"], rule["rule"], rule["added_ms"]) for rule in rules(path)] == [
        ("suricata", "1:2002752", 5), ("snort", "129:14", 7),
    ]
    set_rule(path, "suricata", 1, 2002752, False, now_ms=8)
    assert [rule["rule"] for rule in rules(path)] == ["129:14"]
    assert not list(path.parent.glob(".*.saving"))

    for engine, gid, sid in (("zeek", 1, 2), ("snort", "x", 2), ("snort", 1, 0), ("snort", 1, 2**32)):
        with pytest.raises(ValueError):
            set_rule(path, engine, gid, sid, True, now_ms=9)

    # Before root's ids-rules-off ran, nothing applied; then its status.
    assert listing(path, tmp_path / "none.json")["applied"] is None
    status = tmp_path / "status.json"
    status.write_text(json.dumps({"applied_ms": 10, "rules": [], "engines": {"snort": "reloaded"}}))
    assert listing(path, status)["applied"]["engines"] == {"snort": "reloaded"}


def test_root_s_applier_reads_the_list_only_as_rules(tmp_path):
    applier = _applier()
    path = tmp_path / "rules_off.json"
    set_rule(path, "suricata", 1, 2002752, True, message="ET INFO", now_ms=1)
    set_rule(path, "snort", 129, 14, True, now_ms=2)
    assert applier.rules_in(path) == [("snort", 129, 14), ("suricata", 1, 2002752)]

    for bad in ('{"rules": [{"engine": "snort", "gid": 1, "sid": "2; x"}]}', '{"rules": {}}', "[]", "not json",
                '{"rules": [{"engine": "snort", "gid": true, "sid": 2}]}'):
        path.write_text(bad)
        with pytest.raises(ValueError):
            applier.rules_in(path)


def test_root_s_applier_writes_each_engine_s_suppressions(tmp_path):
    applier = _applier()
    original = "# Suricata's threshold file\nsuppress gen_id 1, sig_id 2, track by_src, ip 10.0.0.1\n\n"
    with_rules = applier.suricata_text(original, [(1, 2002752), (1, 2030387)])
    assert with_rules == (
        "# Suricata's threshold file\nsuppress gen_id 1, sig_id 2, track by_src, ip 10.0.0.1\n\n"
        f"{applier.BEGIN}\nsuppress gen_id 1, sig_id 2002752\nsuppress gen_id 1, sig_id 2030387\n{applier.END}\n"
    )
    # Changed, and taken out again: the file as it was.
    assert applier.suricata_text(with_rules, [(1, 2030387)]).count("suppress gen_id 1, sig_id 2") == 2
    assert applier.suricata_text(with_rules, []) == original.rstrip("\n") + "\n"
    assert applier.snort_text([(129, 14)]) == (
        "-- Written by ids-rules-off: the rules turned off from the dashboard.\n"
        "return {\n    { gid = 129, sid = 14 },\n}\n"
    )
    target = tmp_path / "suppress_dashboard.lua"
    assert applier.write(target, "a\n") is True
    assert applier.write(target, "a\n") is False


def test_root_s_applier_reads_snort_s_reload_messages():
    applier = _applier()
    started = "** caught reload-config signal\nReload started. [signal]\n.. reloading configuration\n"
    assert applier.reload_outcome(started) is None
    assert applier.reload_outcome(started + "Reload ended. [signal]\n") == "reloaded"
    assert applier.reload_outcome(started + "== reload failed - bad config\n").startswith("error")
    assert applier.reload_outcome("Reload in progress [signal], attempting command: [signal]").startswith("error")
