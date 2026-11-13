import json
from pathlib import Path

import pytest

from ids.config import engine_sources, get_settings, read_rule_counts, write_rule_counts

ENGINE_SETTINGS = (
    "IDS_ENGINES", "IDS_SNORT_RULES", "IDS_SNORT_CONFIG", "IDS_SURICATA_RULES",
    "IDS_SURICATA_CONFIG", "IDS_RULE_COUNTS_FILE", "IDS_LOCAL_RULES",
)
REPO_ROOT = Path(__file__).resolve().parents[1]


def _settings(monkeypatch, tmp_path, **values):
    """The settings from these values alone, without the project's .env."""
    monkeypatch.setattr("ids.config.ENV_FILE", tmp_path / "no.env")
    for name in ENGINE_SETTINGS:
        monkeypatch.delenv(name, raising=False)
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    return get_settings()


def test_the_engines_come_from_ids_engines_in_a_fixed_order(monkeypatch, tmp_path):
    assert _settings(monkeypatch, tmp_path).engines == ("snort", "suricata")
    assert _settings(monkeypatch, tmp_path, IDS_ENGINES="Suricata").engines == ("suricata",)
    assert _settings(monkeypatch, tmp_path, IDS_ENGINES="suricata, snort").engines == (
        "snort", "suricata",
    )
    with pytest.raises(ValueError, match="unknown engine zeek"):
        _settings(monkeypatch, tmp_path, IDS_ENGINES="suricata,zeek")
    with pytest.raises(ValueError, match="cannot be empty"):
        _settings(monkeypatch, tmp_path, IDS_ENGINES=" , ")


def test_the_alert_archive_keeps_30_days_in_10_day_zips_unless_set(monkeypatch, tmp_path):
    settings = _settings(monkeypatch, tmp_path)
    assert (settings.alert_archive_dir.name, settings.alert_archive_days, settings.alert_archive_zip_days) == (
        "alert-archive", 30, 10,
    )
    # 0 days: the alerts past the limit are deleted, as before the archive.
    assert _settings(monkeypatch, tmp_path, IDS_ALERT_ARCHIVE_DAYS="0").alert_archive_days == 0
    with pytest.raises(ValueError, match="IDS_ALERT_ARCHIVE_ZIP_DAYS must be >= 1"):
        _settings(monkeypatch, tmp_path, IDS_ALERT_ARCHIVE_ZIP_DAYS="0")


def test_engine_sources_give_each_running_engines_files_and_rule_count(monkeypatch, tmp_path):
    counts = tmp_path / "engine_rule_counts.json"
    settings = _settings(
        monkeypatch, tmp_path,
        IDS_ENGINES="suricata",
        IDS_SURICATA_RULES=str(tmp_path / "suricata.rules"),
        IDS_SURICATA_CONFIG=str(tmp_path / "suricata.yaml"),
        IDS_RULE_COUNTS_FILE=str(counts),
    )

    # No count until a rule update saves one. The local rules both engines
    # share are the project's own, unless set.
    assert engine_sources(settings) == {
        "suricata": {
            "rules": str(tmp_path / "suricata.rules"),
            "local_rules": str(REPO_ROOT / "deploy" / "rules" / "local.rules"),
            "config_file": str(tmp_path / "suricata.yaml"),
            "engine_rule_count": None,
        },
    }
    write_rule_counts(counts, {"snort": 48757, "suricata": 69309})
    assert engine_sources(settings)["suricata"]["engine_rule_count"] == 69309
    # IDS_LOCAL_RULES empty: this machine's engines load no local rules.
    none = _settings(monkeypatch, tmp_path, IDS_ENGINES="suricata", IDS_LOCAL_RULES="")
    assert (none.local_rules, engine_sources(none)["suricata"]["local_rules"]) == (None, None)
    # The usual places when nothing else is set.
    both = _settings(monkeypatch, tmp_path)
    assert {engine: source["config_file"] for engine, source in engine_sources(both).items()} == {
        "snort": "/usr/local/etc/snort/snort.lua",
        "suricata": "/etc/suricata/suricata.yaml",
    }


def test_rule_counts_are_saved_whole_and_anything_else_is_left_out(tmp_path):
    path = tmp_path / "runtime" / "engine_rule_counts.json"

    write_rule_counts(path, {"suricata": 69309, "snort": 48757})

    assert json.loads(path.read_text()) == {"snort": 48757, "suricata": 69309}
    assert list(path.parent.iterdir()) == [path]
    assert read_rule_counts(path) == {"snort": 48757, "suricata": 69309}
    path.write_text('{"snort": "many", "suricata": true, "zeek": 3}')
    assert read_rule_counts(path) == {}
    path.write_text("[48757]")
    assert read_rule_counts(path) == {}
    path.write_text("{")
    assert read_rule_counts(path) == {}
    assert read_rule_counts(tmp_path / "missing.json") == {}


def test_the_basic_local_rules_are_the_same_text_for_both_engines():
    """deploy/rules/local.rules goes to Snort and Suricata alike: local SIDs,
    LOCAL messages, and no content modifiers, which the two engines write
    differently."""
    rules = [
        line for line in (REPO_ROOT / "deploy" / "rules" / "local.rules").read_text().splitlines()
        if line.startswith("alert ")
    ]
    sids = [int(line.split("sid:")[1].split(";")[0]) for line in rules]

    assert rules and len(set(sids)) == len(sids)
    assert all(1_000_000 < sid < 2_000_000 for sid in sids)
    assert all('msg:"LOCAL ' in line for line in rules)
    for modifier in ("nocase", "distance", "within", "depth", "offset"):
        assert not any(f" {modifier}" in line or f";{modifier}" in line for line in rules), modifier


def test_send_goes_to_the_llm_pc_set_in_the_settings(monkeypatch):
    from ids.config import llm_target

    monkeypatch.setenv("IDS_LLM_URL", "")
    monkeypatch.setenv("IDS_LLM_TOKEN", "")
    assert llm_target() == (None, None)
    monkeypatch.setenv("IDS_LLM_URL", " http://192.168.50.20:8000/ids ")
    monkeypatch.setenv("IDS_LLM_TOKEN", "secret")
    assert llm_target() == ("http://192.168.50.20:8000/ids", "secret")
    monkeypatch.setenv("IDS_LLM_URL", "192.168.50.20:8000")
    with pytest.raises(ValueError, match="IDS_LLM_URL must start with http:// or https://"):
        llm_target()
