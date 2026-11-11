from __future__ import annotations

import gzip
import json
import shutil

from ids.rotated_logs import rotated_files
from ids.tailer import PersistentJsonTailer


def _consume_and_ack(tailer, collected):
    tailer.poll(
        lambda line, inode, offset: (
            collected.append(line),
            tailer.acknowledge(inode, offset),
        )
    )


def test_partial_line_is_not_consumed(tmp_path):
    path = tmp_path / "events.json"
    state = tmp_path / "state.json"

    path.write_text(
        '{"id":1}\n{"id":2',
        encoding="utf-8",
    )

    tailer = PersistentJsonTailer(
        path,
        state,
        "test",
        start_at_end=False,
    )

    first = []
    _consume_and_ack(tailer, first)

    assert first == ['{"id":1}']

    with path.open("a", encoding="utf-8") as f:
        f.write("}\n")

    second = []
    _consume_and_ack(tailer, second)

    assert second == ['{"id":2}']


def test_rename_and_recreate_rotation(tmp_path):
    path = tmp_path / "events.json"
    rotated = tmp_path / "events.json.rotated"
    state = tmp_path / "state.json"

    path.write_text(
        '{"id":1}\n{"id":2}\n',
        encoding="utf-8",
    )

    tailer = PersistentJsonTailer(
        path,
        state,
        "test",
        start_at_end=False,
    )

    first = []
    _consume_and_ack(tailer, first)

    old_inode = path.stat().st_ino

    path.rename(rotated)
    path.write_text(
        '{"id":3}\n',
        encoding="utf-8",
    )

    new_inode = path.stat().st_ino

    assert new_inode != old_inode

    restarted = PersistentJsonTailer(
        path,
        state,
        "test",
        start_at_end=True,
    )

    second = []
    _consume_and_ack(restarted, second)

    assert second == ['{"id":3}']


def test_copytruncate_detects_new_content_even_when_larger_than_old_offset(
    tmp_path,
):
    path = tmp_path / "events.json"
    state = tmp_path / "state.json"

    old_lines = [
        json.dumps(
            {
                "id": index,
                "payload": "A" * 80,
            }
        )
        for index in range(1, 6)
    ]

    path.write_text(
        "\n".join(old_lines) + "\n",
        encoding="utf-8",
    )

    tailer = PersistentJsonTailer(
        path,
        state,
        "test",
        start_at_end=False,
    )

    before = []
    _consume_and_ack(tailer, before)

    old_stat = path.stat()
    old_inode = old_stat.st_ino
    old_size = old_stat.st_size

    assert old_size > 256

    new_lines = [
        json.dumps(
            {
                "id": index,
                "payload": "B" * 80,
            }
        )
        for index in range(100, 110)
    ]

    # copytruncate: truncate the same inode and immediately write enough
    # new data that the new file is already larger than the old offset.
    new_content = "\n".join(new_lines) + "\n"

    with path.open("w", encoding="utf-8") as f:
        f.write(new_content)

    new_stat = path.stat()
    new_size = new_stat.st_size

    assert new_stat.st_ino == old_inode
    assert new_size > old_size

    after = []
    _consume_and_ack(tailer, after)

    assert after == new_lines


def test_shared_state_preserves_both_sources(tmp_path):
    state = tmp_path / "state.json"
    snort_path = tmp_path / "snort.json"
    suricata_path = tmp_path / "suricata.json"

    snort_path.write_text(
        '{"id":"snort"}\n',
        encoding="utf-8",
    )

    suricata_path.write_text(
        '{"id":"suricata"}\n',
        encoding="utf-8",
    )

    snort = PersistentJsonTailer(
        snort_path,
        state,
        "snort",
        start_at_end=False,
    )

    suricata = PersistentJsonTailer(
        suricata_path,
        state,
        "suricata",
        start_at_end=False,
    )

    snort_lines = []
    suricata_lines = []

    _consume_and_ack(snort, snort_lines)
    _consume_and_ack(suricata, suricata_lines)

    saved = json.loads(
        state.read_text(encoding="utf-8")
    )

    assert snort_lines == ['{"id":"snort"}']
    assert suricata_lines == ['{"id":"suricata"}']

    assert "snort" in saved
    assert "suricata" in saved

    assert saved["snort"]["fingerprint"]
    assert saved["suricata"]["fingerprint"]

    assert saved["snort"]["fingerprint_length"] > 0
    assert saved["suricata"]["fingerprint_length"] > 0


def test_one_engine_saving_keeps_the_other_engines_newer_position(tmp_path):
    state = tmp_path / "state.json"
    snort_path = tmp_path / "snort.json"
    suricata_path = tmp_path / "suricata.json"
    snort_path.write_text('{"id":"snort-1"}\n', encoding="utf-8")
    suricata_path.write_text('{"id":"suricata-1"}\n', encoding="utf-8")

    # Both positions are already saved when the collector starts again.
    for source, path in (("snort", snort_path), ("suricata", suricata_path)):
        _consume_and_ack(
            PersistentJsonTailer(path, state, source, start_at_end=False), []
        )
    snort = PersistentJsonTailer(snort_path, state, "snort", start_at_end=False)
    suricata = PersistentJsonTailer(suricata_path, state, "suricata", start_at_end=False)

    with snort_path.open("a", encoding="utf-8") as handle:
        handle.write('{"id":"snort-2"}\n')
    with suricata_path.open("a", encoding="utf-8") as handle:
        handle.write('{"id":"suricata-2"}\n')
    snort_lines, suricata_lines = [], []
    _consume_and_ack(snort, snort_lines)
    # Suricata saves after Snort: it must not write back the Snort position
    # it loaded when it started.
    _consume_and_ack(suricata, suricata_lines)

    saved = json.loads(state.read_text(encoding="utf-8"))
    assert (snort_lines, suricata_lines) == (['{"id":"snort-2"}'], ['{"id":"suricata-2"}'])
    assert saved["snort"]["offset"] == snort_path.stat().st_size
    assert saved["suricata"]["offset"] == suricata_path.stat().st_size

    # A restart reads neither engine's lines again.
    again = []
    _consume_and_ack(PersistentJsonTailer(snort_path, state, "snort", start_at_end=False), again)
    assert again == []


def _lines(start, stop, letter="A"):
    return [json.dumps({"id": index, "payload": letter * 80}) for index in range(start, stop)]


def _write(path, lines, mode="w"):
    with path.open(mode, encoding="utf-8") as f:
        f.write("".join(f"{line}\n" for line in lines))


def test_lines_written_just_before_a_copytruncate_are_read_from_the_copy(tmp_path):
    path = tmp_path / "eve.json"
    state = tmp_path / "state.json"
    _write(path, _lines(1, 4))
    tailer = PersistentJsonTailer(path, state, "suricata", start_at_end=False)
    before = []
    _consume_and_ack(tailer, before)

    # Written after the last poll, then copied out and truncated (logrotate's
    # compress + copytruncate), and new lines into the emptied log.
    _write(path, _lines(4, 6), "a")
    (tmp_path / "eve.json.1.gz").write_bytes(gzip.compress(path.read_bytes()))
    _write(path, _lines(100, 103, "B"))

    after = []
    _consume_and_ack(tailer, after)

    assert before == _lines(1, 4)
    assert after == _lines(4, 6) + _lines(100, 103, "B")
    assert json.loads(state.read_text())["suricata"]["offset"] == path.stat().st_size


def test_a_restart_after_two_rotations_reads_what_both_copies_missed(tmp_path):
    path = tmp_path / "alert_json.txt"
    state = tmp_path / "state.json"
    _write(path, _lines(1, 4))
    first = []
    _consume_and_ack(PersistentJsonTailer(path, state, "snort", start_at_end=True), first)
    _consume_and_ack(PersistentJsonTailer(path, state, "snort", start_at_end=True), first)
    assert first == []  # Started at the end.

    # While the collector is stopped: more lines, a rotation (delaycompress:
    # the newest copy stays plain), more lines, another rotation.
    _write(path, _lines(4, 6), "a")
    shutil.copy(path, tmp_path / "alert_json.txt.1")
    _write(path, _lines(10, 13, "B"))
    (tmp_path / "alert_json.txt.2.gz").write_bytes(gzip.compress((tmp_path / "alert_json.txt.1").read_bytes()))
    shutil.copy(path, tmp_path / "alert_json.txt.1")
    _write(path, _lines(20, 22, "C"))
    # An older copy, from before the saved position, isn't read.
    (tmp_path / "alert_json.txt.3.gz").write_bytes(gzip.compress(b'{"id": 0}\n'))

    restarted = PersistentJsonTailer(path, state, "snort", start_at_end=True)
    after = []
    _consume_and_ack(restarted, after)

    assert after == _lines(4, 6) + _lines(10, 13, "B") + _lines(20, 22, "C")
    again = []
    _consume_and_ack(PersistentJsonTailer(path, state, "snort", start_at_end=True), again)
    assert again == []


def test_without_the_rotated_copy_the_new_log_is_still_read(tmp_path):
    path = tmp_path / "eve.json"
    state = tmp_path / "state.json"
    _write(path, _lines(1, 4))
    _consume_and_ack(PersistentJsonTailer(path, state, "suricata", start_at_end=False), [])

    _write(path, _lines(100, 102, "B"))
    after = []
    _consume_and_ack(PersistentJsonTailer(path, state, "suricata", start_at_end=True), after)

    assert after == _lines(100, 102, "B")


def test_rotated_copies_are_listed_newest_first(tmp_path):
    for name in ("eve.json", "eve.json.2.gz", "eve.json.10.gz", "eve.json.1", "eve.json.1.gz",
                 "eve.json.tmp", "eve.json.old.1x", "other.json.1"):
        (tmp_path / name).write_text("")

    assert [path.name for path in rotated_files(tmp_path / "eve.json")] == [
        "eve.json.1", "eve.json.1.gz", "eve.json.2.gz", "eve.json.10.gz",
    ]
