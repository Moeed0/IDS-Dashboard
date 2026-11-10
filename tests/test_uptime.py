import json
import subprocess

from ids.uptime import machine_off_periods, off_during


def _journal(boots):
    """A journalctl run that lists these boots, as (first, last) in ms."""

    def run(command, **options):
        assert command[:2] == ["journalctl", "--list-boots"]
        listed = [
            {"index": index, "boot_id": f"boot{index}", "first_entry": first * 1000, "last_entry": last * 1000}
            for index, (first, last) in enumerate(boots)
        ]
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(listed), stderr="")

    return run


def test_the_machine_was_off_from_one_boots_last_entry_to_the_next_ones_first():
    # Listed newest first, as journalctl may: the order is the times'.
    boots = [(5_000, 9_000), (1_000, 2_000), (2_500, 4_000)]

    assert machine_off_periods(_journal(boots)) == [(2_000, 2_500), (4_000, 5_000)]


def test_without_a_readable_journal_no_off_times_are_known():
    def failing(command, **options):
        raise subprocess.CalledProcessError(1, command, stderr="No journal files were found.")

    def missing(command, **options):
        raise FileNotFoundError("journalctl")

    assert machine_off_periods(failing) == []
    assert machine_off_periods(missing) == []


def test_a_window_gets_the_off_times_that_overlap_it_whole():
    periods = [(100, 200), (300, 400), (500, 600)]

    assert off_during(periods, 150, 350) == [[100, 200], [300, 400]]
    assert off_during(periods, 600, 700) == []
