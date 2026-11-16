import pytest

from ids.alert_classification import is_pass_through_action


@pytest.mark.parametrize(
    ("action", "expected"),
    [
        ("allow", True),      # Snort
        ("allowed", True),    # Suricata
        ("Allowed", True),
        ("drop", False),
        ("blocked", False),
        (None, False),
    ],
)
def test_pass_through_actions(action, expected):
    assert is_pass_through_action(action) is expected
