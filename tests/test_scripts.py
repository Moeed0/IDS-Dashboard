import io

import pytest

import scripts.download_intel_sources as download
from scripts.save_rule_counts import suricata_count

META = "lastModifiedDate:2026-11-05T03:00:00-04:00\nsize:100\ngzSize:4\nsha256:AA\n"


def test_suricata_count_is_the_last_start_in_its_log(tmp_path):
    log = tmp_path / "suricata.log"
    log.write_text(
        "Info: detect: 2 rule files processed. 68816 rules successfully loaded, 7 rules failed\n"
        "Info: runmodes: ens38: creating 8 threads\n"
        "Info: detect: 2 rule files processed. 69309 rules successfully loaded, 7 rules failed\n"
    )
    assert suricata_count(log) == 69309
    (tmp_path / "quiet.log").write_text("Notice: threads: Threads created\n")
    with pytest.raises(ValueError, match="rules successfully loaded"):
        suricata_count(tmp_path / "quiet.log")


def _fake_site(monkeypatch, meta=META, feed=b"gzip"):
    """NVD's feeds without the network: what each request asked for."""
    asked = []

    def answer(url):
        asked.append(url.rsplit("/", 1)[1])
        return io.BytesIO(meta.encode() if url.endswith(".meta") else feed)

    monkeypatch.setattr(download, "_open", answer)
    return asked


def test_an_unchanged_nvd_feed_is_not_downloaded_again(tmp_path, monkeypatch):
    asked = _fake_site(monkeypatch)
    download.download_nvd(tmp_path, [2002])
    assert asked == [
        "nvdcve-2.0-2002.meta", "nvdcve-2.0-2002.json.gz",
        "nvdcve-2.0-modified.meta", "nvdcve-2.0-modified.json.gz",
    ]
    assert (tmp_path / "nvdcve-2.0-2002.json.gz").read_bytes() == b"gzip"
    assert not list(tmp_path.glob("*.part"))

    asked.clear()
    download.download_nvd(tmp_path, [2002])
    # Only the small .meta files, to see that nothing changed.
    assert asked == ["nvdcve-2.0-2002.meta", "nvdcve-2.0-modified.meta"]

    asked = _fake_site(monkeypatch, META.replace("03:00:00", "04:00:00"))
    download.download_nvd(tmp_path, [2002])
    assert "nvdcve-2.0-2002.json.gz" in asked


def test_a_short_nvd_download_is_an_error(tmp_path, monkeypatch):
    _fake_site(monkeypatch, feed=b"gz")
    with pytest.raises(RuntimeError, match="got 2 bytes, the feed says 4"):
        download.download_nvd(tmp_path, [2002])
    # The feed's .meta is saved only with a complete download.
    assert not (tmp_path / "nvdcve-2.0-2002.meta").exists()
