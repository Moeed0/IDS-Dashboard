from ids.community_id import community_id


def test_tcp_community_id_is_direction_independent():
    forward = community_id(
        "192.168.50.141",
        54230,
        "192.168.50.114",
        80,
        "TCP",
    )

    reverse = community_id(
        "192.168.50.114",
        80,
        "192.168.50.141",
        54230,
        "TCP",
    )

    assert forward == reverse
    assert forward.startswith("1:")


def test_same_flow_is_stable():
    first = community_id(
        "192.168.50.141",
        53186,
        "192.168.50.114",
        445,
        "TCP",
    )

    second = community_id(
        "192.168.50.141",
        53186,
        "192.168.50.114",
        445,
        "TCP",
    )

    assert first == second


def test_different_flow_changes_id():
    first = community_id(
        "192.168.50.141",
        53186,
        "192.168.50.114",
        445,
        "TCP",
    )

    second = community_id(
        "192.168.50.141",
        53187,
        "192.168.50.114",
        445,
        "TCP",
    )

    assert first != second


# Expected values below were written by Suricata 8.0.3 on the lab network.

def test_tcp_and_udp_match_suricata():
    assert community_id(
        "192.168.50.141", 36788, "192.168.50.114", 80, "TCP",
    ) == "1:VtLM8w9QQw/rxKkhooBa20VkAO0="
    assert community_id(
        "192.168.50.122", 54448, "192.168.50.1", 53, "UDP",
    ) == "1:Y74aYpWpg4CrnOG6NgyH9larIWE="


def test_icmp_echo_matches_suricata_and_the_reply_has_the_same_id():
    request = community_id("192.168.50.1", 8, "192.168.50.122", 0, "ICMP")
    reply = community_id("192.168.50.122", 0, "192.168.50.1", 0, "ICMP")

    assert request == "1:uNz8fP4aPzSVKDRnYe38lmEc5gk="
    assert reply == request


def test_icmpv6_matches_suricata_for_paired_and_one_way_types():
    # 130 (MLD query) pairs with 131; 143 (MLDv2 report) is one-way.
    assert community_id(
        "::", 130, "ff02::1", 0, "IPv6-ICMP",
    ) == "1:Ulw23EzIdEynP438jyFOLcsvifc="
    assert community_id(
        "fe80::2d37:6cf4:f5c8:64f7", 143, "ff02::16", 0, "IPv6-ICMP",
    ) == "1:u9VVTsaFK5CP4k9iGfOIScA00Cs="


def test_protocols_without_ports_ignore_port_values():
    assert community_id(
        "192.168.50.1", 5, "224.0.0.1", 6, "IGMP",
    ) == community_id("192.168.50.1", None, "224.0.0.1", None, "IGMP")
