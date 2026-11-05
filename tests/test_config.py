import json

import pytest

from ids.config import engine_sources, get_settings, read_rule_counts, write_rule_counts

ENGINE_SETTINGS = (
    "IDS_ENGINES", "IDS_SNORT_RULES", "IDS_SNORT_CONFIG", "IDS_SURICATA_RULES",
    "IDS_SURICATA_CONFIG", "IDS_RULE_COUNTS_FILE",
)


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


def test_engine_sources_give_each_running_engines_files_and_rule_count(monkeypatch, tmp_path):
    counts = tmp_path / "engine_rule_counts.json"
    settings = _settings(
        monkeypatch, tmp_path,
        IDS_ENGINES="suricata",
        IDS_SURICATA_RULES=str(tmp_path / "suricata.rules"),
        IDS_SURICATA_CONFIG=str(tmp_path / "suricata.yaml"),
        IDS_RULE_COUNTS_FILE=str(counts),
    )

    # No count until a rule update saves one.
    assert engine_sources(settings) == {
        "suricata": {
            "rules": str(tmp_path / "suricata.rules"),
            "config_file": str(tmp_path / "suricata.yaml"),
            "engine_rule_count": None,
        },
    }
    write_rule_counts(counts, {"snort": 48757, "suricata": 69309})
    assert engine_sources(settings)["suricata"]["engine_rule_count"] == 69309
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
