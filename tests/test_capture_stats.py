from datetime import datetime

from ids.capture_stats import snort_last_hour, suricata_last_hour

# 10 November 2026, 12:00:00 local time, as both engines write it.
NOON = int(datetime(2026, 11, 10, 12, 0, 0).timestamp() * 1000)


def test_snort_adds_up_its_minutes_of_the_last_hour(tmp_path):
    path = tmp_path / "perf_monitor_base.csv"
    second = NOON // 1000
    path.write_text(
        "#timestamp,ac_bnfa.searches,daq.received,daq.analyzed,daq.dropped\n"
        # Over an hour ago: left out.
        f"{second - 3_700},5,900,900,9\n"
        f"{second - 120},5,70,68,2\n"
        # Snort started again, with its columns in another order.
        "#timestamp,daq.dropped,daq.received\n"
        f"{second - 60},1,30\n"
        f"{second},0,25\n"
    )

    assert snort_last_hour(path, NOON) == {"packets": 125, "dropped": 3, "minutes": 3}


def test_snort_without_its_file_or_columns_says_nothing(tmp_path):
    other = tmp_path / "other.csv"
    other.write_text("#timestamp,ac_bnfa.searches\n1794293543,77\n")

    assert snort_last_hour(tmp_path / "missing.csv", NOON) is None
    assert snort_last_hour(other, NOON) is None


def _suricata_block(clock, uptime, packets, drops=None):
    lines = [
        "-" * 84,
        f"Date: 11/10/2026 -- {clock} (uptime: {uptime})",
        "-" * 84,
        "Counter                                       | TM Name                   | Value",
        "-" * 84,
        f"capture.kernel_packets                        | Total                     | {packets}",
    ]
    # stats.log leaves out a counter that is 0.
    if drops is not None:
        lines.append(f"capture.kernel_drops                          | Total                     | {drops}")
    lines.append(f"decoder.pkts                                  | Total                     | {packets}")
    return "\n".join(lines) + "\n"


def test_suricata_counts_the_last_hour_of_its_totals(tmp_path):
    path = tmp_path / "stats.log"
    path.write_text(
        _suricata_block("10:58:00", "0d, 02h 58m 00s", 5_000)
        + _suricata_block("11:01:00", "0d, 03h 01m 00s", 6_000, drops=4)
        + _suricata_block("12:00:00", "0d, 04h 00m 00s", 9_000, drops=10)
    )

    # From the 11:01 block, the oldest within the hour.
    assert suricata_last_hour(path, NOON) == {"packets": 3_000, "dropped": 6, "minutes": 59}


def test_suricata_started_in_the_last_hour_counts_since_it_started(tmp_path):
    path = tmp_path / "stats.log"
    path.write_text(
        _suricata_block("11:10:00", "0d, 05h 00m 00s", 50_000, drops=40)
        # Started again at 11:30.
        + _suricata_block("11:31:00", "0d, 00h 01m 00s", 100)
        + _suricata_block("12:00:00", "0d, 00h 30m 00s", 1_200)
    )

    assert suricata_last_hour(path, NOON) == {"packets": 1_200, "dropped": 0, "minutes": 30}
    assert suricata_last_hour(tmp_path / "missing.log", NOON) is None
