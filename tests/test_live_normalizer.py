"""Snort's alert_json rows as the collector stores them."""

from ids.live_normalizer import normalize_snort


def _snort(**fields):
    return {
        "timestamp": "11/13-12:50:44.920849",
        "proto": "IP",
        "src_addr": "192.168.50.122",
        "dst_addr": "224.0.0.252",
        "msg": "(ipv4) IPv4 option set",
        "rule": "116:444:1",
        "gid": 116,
        "sid": 444,
        "rev": 1,
        "priority": 3,
        **fields,
    }


def test_the_app_openappid_named_is_kept():
    assert normalize_snort(_snort(app_id="IGMP"))["app"] == "IGMP"


def test_no_app_is_none():
    # Before OpenAppID's detectors, or a flow it couldn't name.
    assert normalize_snort(_snort())["app"] is None
    assert normalize_snort(_snort(app_id=" "))["app"] is None
