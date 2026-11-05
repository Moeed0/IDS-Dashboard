from ids.alert_intelligence import _clean_documentation
from ids.extended_alert_intelligence import (
    _content_patterns,
    _describe_rule_logic,
    _rule_reference_cves,
)


def test_snort_style_references_become_cve_ids():
    rule = {"references_json": '["cve,2014-6271", "cve,2014-6277", "url,example.com"]'}
    assert _rule_reference_cves(rule) == ["CVE-2014-6271", "CVE-2014-6277"]


def test_reference_parsing_is_defensive():
    assert _rule_reference_cves(None) == []
    assert _rule_reference_cves({}) == []
    assert _rule_reference_cves({"references_json": "not json"}) == []
    assert _rule_reference_cves({"references_json": ["CVE,2014-6271"]}) == ["CVE-2014-6271"]


def test_content_patterns_handle_both_stored_shapes():
    snort = {"content_matches_json": '["\\"() {\\",fast_pattern,nocase"]'}
    suricata = {"content_matches_json": '[" HTTP/1.", "\\"|28 29 20 7b|\\"; fast_pattern"]'}
    assert _content_patterns(snort) == ["() {"]
    assert _content_patterns(suricata) == ["HTTP/1.", "|28 29 20 7b|"]


def test_rule_logic_description_uses_only_rule_fields():
    rule = {
        "protocol": "tcp",
        "service": "http",
        "flow": "to_server,established",
        "content_matches_json": '["\\"() {\\",fast_pattern,nocase"]',
    }
    text = _describe_rule_logic(rule)
    assert "TCP traffic" in text and "http service" in text
    assert "sent to a server" in text and "established session" in text
    assert "`() {`" in text


def test_rule_logic_falls_back_when_rule_has_no_detail():
    assert _describe_rule_logic({}) == "The traffic matched the conditions defined by the IDS rule."


def test_placeholder_documentation_is_dropped_but_real_text_kept():
    cleaned = _clean_documentation(
        {
            "rule_explanation": "None provided",
            "what_to_look_for": "No information provided.",
            "known_usage": "No public information",
            "false_positives": "No known false positives",
            "msg": "x",
            "sid": 401,
        }
    )
    assert "rule_explanation" not in cleaned
    assert "what_to_look_for" not in cleaned
    assert "known_usage" not in cleaned
    assert cleaned["false_positives"] == "No known false positives"
    assert cleaned["sid"] == 401


SNORT_SHELLSHOCK_RULE = (
    'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS ( msg:"OS-OTHER Bash CGI '
    'environment variable injection attempt"; flow:to_server,established; http_header; '
    'content:"() {",fast_pattern,nocase; metadata:policy balanced-ips drop; service:http; '
    'reference:cve,2014-6271; classtype:attempted-admin; sid:31978; rev:5; )'
)
SURICATA_SHELLSHOCK_RULE = (
    'alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2014-6271 '
    'Attempt in Headers"; flow:established,to_server; http.header; content:"|28 29 20 7b|"; '
    'fast_pattern; content:"bash|20 2d|c"; reference:url,example.com; sid:2019232; rev:7;)'
)


def test_rule_conditions_track_snort_buffer_and_nocase():
    from ids.extended_alert_intelligence import _rule_conditions

    assert _rule_conditions(SNORT_SHELLSHOCK_RULE) == [{
        "type": "content", "buffer": "HTTP headers", "pattern": "() {",
        "negated": False, "nocase": True,
    }]


def test_rule_conditions_decode_printable_hex_and_keep_order():
    from ids.extended_alert_intelligence import _rule_conditions

    conditions = _rule_conditions(SURICATA_SHELLSHOCK_RULE)
    assert [c["decoded"] for c in conditions] == ["() {", "bash -c"]
    assert all(c["buffer"] == "HTTP headers" for c in conditions)
    assert conditions[0]["pattern"] == "|28 29 20 7b|"


def test_rule_conditions_handle_negation_pcre_and_binary_hex():
    from ids.extended_alert_intelligence import _describe_rule_logic, _rule_conditions

    rule_text = (
        'alert tcp any any -> any any (msg:"x"; http.uri; content:!"/ok"; '
        'pcre:"/a+b/i"; pkt_data; content:"|00 01|"; sid:1;)'
    )
    conditions = _rule_conditions(rule_text)
    assert conditions[0]["negated"] is True
    assert conditions[1]["type"] == "pcre"
    assert "decoded" not in conditions[2]
    text = _describe_rule_logic({"protocol": "tcp", "rule_text": rule_text})
    assert "the HTTP URI does not contain `/ok`" in text
    assert (
        "the HTTP URI matches the regular expression: `a`, 1 or more times, "
        "then `b` (case-insensitive)"
    ) in text
    assert "the packet payload contains the bytes 0x00 0x01" in text


def test_rule_logic_words_patterns_without_backslashes():
    # A JSON file writes each backslash twice, so \x81 would read differently
    # from one program to the next; the rule text keeps the pattern as written.
    rule_text = (
        'alert udp $DNS_SERVERS 53 -> any any (msg:"ET DNS Standard query response, '
        'Refused"; pcre:"/^..[\\x81\\x82\\x83\\x84\\x85\\x86\\x87]\\x85/"; '
        'classtype:not-suspicious; sid:2001119; rev:6;)'
    )
    assert _describe_rule_logic({"protocol": "udp", "rule_text": rule_text}) == (
        "The rule inspects UDP traffic. It alerts only when the source port is 53; and "
        "the inspected data matches the regular expression: at the start, any 2 bytes "
        "other than 0x0a, then a byte from 0x81 to 0x87, then the byte 0x85."
    )
    rule_text = (
        'alert ip any any -> any any ( msg:"LOCAL test rule with escaped content"; '
        'ip_proto:2; content:"|11|",depth 1; content:"Host|3A| x\\;y"; '
        'pcre:"/[[:alpha:]]+/"; sid:1000001; rev:1; )'
    )
    text = _describe_rule_logic({"protocol": "ip", "rule_text": rule_text})
    assert text == (
        "The rule inspects IP traffic. It alerts only when the inspected data contains "
        "the byte 0x11; the inspected data contains `Host: x;y`; and the inspected data "
        "matches the regular expression in the rule text."
    )
    assert "\\" not in text


def test_rule_logic_uses_rule_text_conditions():
    text = _describe_rule_logic({
        "protocol": "tcp", "service": "http", "flow": "to_server,established",
        "rule_text": SNORT_SHELLSHOCK_RULE,
    })
    assert "the HTTP headers contain `() {` (case-insensitive)" in text
    assert "metadata" not in text and "policy" not in text


def test_explanation_describes_alert_not_vendor_cve_text():
    from ids.extended_alert_intelligence import _build_explanation

    nvd_text = "GNU Bash through 4.3 processes trailing strings after function definitions."
    explanation = _build_explanation(
        {
            "engine": "snort", "msg": "OS-OTHER Bash CGI", "protocol": "TCP",
            "src_addr": "192.168.50.141", "src_port": 36788,
            "dst_addr": "192.168.50.114", "dst_port": 80, "service": "http",
        },
        {
            "rule": {"protocol": "tcp", "rule_text": SNORT_SHELLSHOCK_RULE},
            "documentation": {
                "rule_explanation": nvd_text,
                "what_to_look_for": "This rule alerts when attempts to exploit CVE-2014-6278 are detected",
            },
        },
        ["CVE-2014-6271", "CVE-2014-6278"], [], {},
    )

    assert nvd_text not in explanation["what_happened"]
    assert "192.168.50.141:36788 to 192.168.50.114:80" in explanation["what_happened"]
    assert "not shown" in explanation["what_happened"]
    assert "`() {`" in explanation["why_triggered"]
    assert "CVE-2014-6278" not in explanation["why_triggered"]
    assert explanation["explanation_source"] == "alert_fields_and_rule_text"
    assert explanation["why_triggered"] not in explanation["what_to_check"]


def _vuln(version, score, kev=None):
    return {"nvd": {"cvss": {"version": version, "base_score": score}}, "cisa_kev": kev}


def test_highest_cvss_prefers_v3_over_higher_v2():
    from ids.extended_alert_intelligence import _highest_cvss

    highest = _highest_cvss({
        "CVE-2014-6271": _vuln("3.1", 9.8),
        "CVE-2014-6277": _vuln("2.0", 10.0),
    })
    assert highest == {
        "cve": "CVE-2014-6271", "base_score": 9.8,
        "version": "3.1", "basis": "cvss_v3_or_later",
    }


def test_highest_cvss_falls_back_to_v2_and_label_says_so():
    from ids.extended_alert_intelligence import _highest_cvss, _priority_guidance

    highest = _highest_cvss({"CVE-2001-0001": _vuln("2.0", 9.3)})
    assert highest["basis"] == "cvss_v2"

    label = _priority_guidance(highest["base_score"], None, False, highest["version"])
    assert label["label"] == "Critical vulnerability context"
    assert "no CVSS v3 score is available" in label["reason"]


def _actions(vulnerabilities):
    from ids.extended_alert_intelligence import _build_explanation

    return _build_explanation(
        {"msg": "x"}, {"rule": {}, "documentation": {}},
        sorted(vulnerabilities), [], vulnerabilities,
    )["recommended_actions"]


def test_recommendations_scale_with_cvss():
    critical = _actions({"CVE-1": _vuln("3.1", 9.8)})
    high = _actions({"CVE-1": _vuln("3.1", 7.5)})
    low = _actions({"CVE-1": _vuln("3.1", 4.3)})

    assert critical[0].startswith("Check this destination first: CVE-1 scores 9.8 (CVSS v3.1)")
    assert high[0].startswith("Check the destination during routine triage")
    assert low[0].startswith("Treat the associated CVEs as context")
    assert not any("security update" in item for item in low)


def test_kev_raises_low_score_to_top_tier():
    actions = _actions({"CVE-1": _vuln("3.1", 5.0, kev={"cveID": "CVE-1"})})

    assert actions[0].startswith("Prioritize checking the affected asset")
    assert actions[1].startswith("Check this destination first")


def test_cve_without_score_keeps_generic_advice():
    actions = _actions({"CVE-1": {"nvd": {}}})

    assert "Check the affected product/version" in actions[0]


def test_rule_logic_names_icmp_type_before_code():
    # Snort lists icode before itype in this rule.
    rule_text = (
        'alert icmp $EXTERNAL_NET any -> $HOME_NET any ( msg:"PROTOCOL-ICMP '
        'Destination Unreachable Network Unreachable"; icode:0; itype:3; '
        'classtype:misc-activity; sid:401; rev:9; )'
    )
    assert _describe_rule_logic({"protocol": "icmp", "rule_text": rule_text}) == (
        "The rule inspects ICMP traffic. It alerts only when the ICMP type is 3 "
        "(Destination Unreachable); and the ICMP code is 0 (Network Unreachable)."
    )


def test_rule_logic_describes_suricata_stream_events():
    rule_text = (
        'alert tcp any any -> any any (msg:"SURICATA STREAM ESTABLISHED packet out '
        'of window"; stream-event:est_packet_out_of_window; threshold:type backoff, '
        'track by_flow, count 1, multiplier 10; classtype:protocol-command-decode; '
        'sid:2210020; rev:3;)'
    )
    assert _describe_rule_logic({"protocol": "tcp", "rule_text": rule_text}) == (
        "The rule inspects TCP traffic. It alerts only when Suricata's TCP stream "
        "engine reports the `est_packet_out_of_window` event."
    )


def test_rule_logic_names_literal_header_addresses_and_ports():
    # Fires on every IPv6 packet to a multicast address: no content check.
    rule_text = (
        'alert ipv6 any any -> ff00::/8 any (msg:"ET EXPLOIT Possible '
        'CVE-2020-11899 Multicast out-of-bound read"; classtype:attempted-admin; '
        'sid:2030387; rev:2;)'
    )
    assert _describe_rule_logic({"protocol": "ipv6", "rule_text": rule_text}) == (
        "The rule inspects IPV6 traffic. It alerts only when the destination "
        "address is in ff00::/8."
    )
    # $VARIABLES depend on the sensor's configuration and are left out.
    rule_text = (
        'alert udp $DNS_SERVERS 53 -> any any (msg:"ET DNS Standard query '
        'response, Refused"; sid:2001119; rev:6;)'
    )
    assert _describe_rule_logic({"protocol": "udp", "rule_text": rule_text}) == (
        "The rule inspects UDP traffic. It alerts only when the source port is 53."
    )


def test_rule_logic_words_port_ranges():
    from ids.extended_alert_intelligence import _header_literal_checks

    assert _header_literal_checks("alert tcp any 1024: -> any any (") == [
        "the source port is 1024 or higher"
    ]
    assert _header_literal_checks("alert tcp any !:1023 -> any [80,8000:8080] (") == [
        "the source port is not 1023 or lower",
        "the destination port is in 80, 8000 to 8080",
    ]


def test_rule_logic_describes_suricata_packet_header_rules():
    rule_text = (
        'alert pkthdr any any -> any any (msg:"SURICATA IPv4 padding required "; '
        'decode-event:ipv4.opt_pad_required; sid:2200007; rev:2;)'
    )
    assert _describe_rule_logic({"protocol": "pkthdr", "rule_text": rule_text}) == (
        "The rule inspects packet headers. It alerts only when Suricata's packet "
        "decoder reports the `ipv4.opt_pad_required` event."
    )


def test_builtin_snort_rules_are_described_without_rule_text():
    from ids.extended_alert_intelligence import _describe_builtin_rule

    assert _describe_builtin_rule({
        "engine": "snort", "gid": 129, "sid": 15,
        "msg": "(stream_tcp) reset outside window",
    }) == (
        "A built-in Snort rule (129:15): Snort's stream_tcp component raised this "
        "event while decoding or inspecting the traffic. Built-in rules have no "
        "rule text; the message names the check that failed."
    )
    # Text rules (GID 1) and Suricata rules are described from their rule text.
    assert _describe_builtin_rule({"engine": "snort", "gid": 1, "sid": 401}) is None
    assert _describe_builtin_rule({"engine": "suricata", "gid": 129, "sid": 1}) is None
