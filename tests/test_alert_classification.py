import pytest

from ids.alert_classification import classify_alert, is_pass_through_action


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        (
            "OS-WINDOWS Microsoft Windows UPnP malformed advertisement",
            "NETWORK_EVENT",
        ),
        ("SURICATA Ethertype unknown", "NETWORK_EVENT"),
        (
            "PROTOCOL-ICMP IPv6 MLD multicast listener query attempt",
            "NETWORK_EVENT",
        ),
        ("POLICY-OTHER IGMP membership query attempt", "NETWORK_EVENT"),
        ("PROTOCOL-ICMP PING", "NETWORK_EVENT"),
        ("ET INFO Windows Update P2P Activity", "NETWORK_EVENT"),
        (
            "ET INFO External IP Lookup Domain in DNS Lookup",
            "NETWORK_EVENT",
        ),
        (
            "SURICATA STREAM excessive retransmissions",
            "NETWORK_EVENT",
        ),
        (
            "POLICY-OTHER HTTP request by IPv4 address attempt",
            "SECURITY_SUPPORT",
        ),
        ("SERVER-WEBAPP test.cgi access", "SECURITY_SUPPORT"),
        # Snort sid 835: the same CGI test page, spelled with a hyphen.
        ("SERVER-WEBAPP test-cgi access", "SECURITY_SUPPORT"),
        # Detections seen when replaying the lab attack pcaps.
        ("ET SCAN NMAP -sS window 1024", "SECURITY_ALERT"),
        ("PROTOCOL-FTP Bad login", "SECURITY_ALERT"),
        ("APP-DETECT FTP 530 Login failed response", "SECURITY_ALERT"),
        ("SERVER-WEBAPP /etc/passwd file access attempt", "SECURITY_ALERT"),
        (
            "SERVER-WEBAPP Apache HTTP Server httpd directory traversal attempt",
            "SECURITY_ALERT",
        ),
        (
            "ET ATTACK_RESPONSE Metasploit Meterpreter File Upload Detected",
            "SECURITY_ALERT",
        ),
        (
            "(http_inspect) URI path contains /../ pattern moving up a directory",
            "SECURITY_SUPPORT",
        ),
        ("ET INFO curl User-Agent Outbound", "SECURITY_SUPPORT"),
        ("GPL NETBIOS SMB-DS IPC$ share access", "SECURITY_SUPPORT"),
        # Routine UPnP discovery stays routine despite the "SCAN" category.
        ("INDICATOR-SCAN UPnP service discover attempt", "NETWORK_EVENT"),
        (
            "OS-OTHER Bash CGI environment variable injection attempt",
            "SECURITY_ALERT",
        ),
        (
            "ET WEB_SERVER Possible CVE-2014-6271 Attempt",
            "SECURITY_ALERT",
        ),
    ],
)
def test_classification_examples(message, expected):
    assert classify_alert({"msg": message}) == expected


def test_missing_message_is_network_event():
    assert classify_alert({}) == "NETWORK_EVENT"


def test_rule_field_is_used_when_message_is_missing():
    assert classify_alert({
        "rule": "OS-OTHER Bash CGI environment variable injection attempt"
    }) == "SECURITY_ALERT"


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
