from ids.export_cleanup import drop_default_gid


def test_default_gid_and_snort_rule_triple_are_dropped_at_every_level():
    document = {
        "native_event": {
            "gid": 1, "sid": 31978, "rev": 5, "rule": "1:31978:5", "msg": "x",
        },
        "detections": [{"alert": {"gid": "1", "signature_id": 2019232}}],
    }

    assert drop_default_gid(document) == {
        "native_event": {"sid": 31978, "rev": 5, "msg": "x"},
        "detections": [{"alert": {"signature_id": 2019232}}],
    }


def test_other_gids_and_unrelated_rule_fields_are_kept():
    # Snort's built-in inspectors use their own GIDs, which identify the rule.
    built_in = {"gid": 129, "sid": 15, "rev": 1, "rule": "129:15:1"}
    assert drop_default_gid(built_in) == built_in

    # The live database's "rule" column holds the message, not gid:sid:rev.
    row = {"gid": 1, "sid": 31978, "rev": 5, "rule": "OS-OTHER Bash CGI attempt"}
    assert drop_default_gid(row) == {
        "sid": 31978, "rev": 5, "rule": "OS-OTHER Bash CGI attempt",
    }
