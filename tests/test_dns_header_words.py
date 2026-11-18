from ids.dns_header_words import dns_header_words


def test_a_responses_flags_and_response_code_are_read_out():
    # 2001119 "ET DNS Standard query response, Refused".
    words = dns_header_words(
        'alert udp $DNS_SERVERS 53 -> any any (msg:"ET DNS Standard query response, Refused"; '
        'pcre:"/^..[\\x81\\x82\\x83\\x84\\x85\\x86\\x87]\\x85/"; sid:2001119; rev:6;)'
    )
    assert words == (
        "Read as the DNS header (RFC 1035): bytes 1-2, the transaction ID, can be any value without a 0x0a byte; "
        "byte 3 (0x81 to 0x87) means a response (QR=1) to a standard query (opcode 0, QUERY), "
        "with at least one of AA (authoritative answer), TC (truncated) or RD (recursion desired) "
        "set; byte 4 (0x85) means RA (recursion available) set, AD (authenticated data) not set, "
        "CD (checking disabled) not set, response code 5, Refused (the server refused to answer)."
    )


def test_a_content_pinned_to_a_place_reads_as_the_header_fields_there():
    words = dns_header_words(
        'alert udp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"x"; '
        'content:"|01 00 00 01 00 00 00 00 00 00|",depth 10,offset 2; sid:1;)'
    )
    assert words == (
        "Read as the DNS header (RFC 1035): byte 3 (0x01) means a query (QR=0), a standard query "
        "(opcode 0, QUERY), with AA (authoritative answer) not set, TC (truncated) not set, RD "
        "(recursion desired) set; byte 4 (0x00) means RA (recursion available) not set, AD "
        "(authenticated data) not set, CD (checking disabled) not set, response code 0, NoError "
        "(no error); bytes 5-6 mean a question count of 1; bytes 7-8 mean an answer count of 0; "
        "bytes 9-10 mean an authority record count of 0; bytes 11-12 mean an additional record "
        "count of 0."
    )


def test_only_udp_port_53_with_a_match_at_one_place_is_read_as_dns():
    # A port list that has 53 is often another protocol.
    assert dns_header_words(
        'alert udp $HOME_NET any -> $EXTERNAL_NET [53,443,9000] (msg:"x"; content:"|30 00|",depth 2; sid:1;)'
    ) is None
    # depth 4 for 2 bytes: they may start at byte 3, 4 or 5.
    assert dns_header_words(
        'alert udp $EXTERNAL_NET 53 -> $HOME_NET any (msg:"x"; content:"|81 80|",depth 4,offset 2; sid:1;)'
    ) is None
    assert dns_header_words(
        'alert tcp $EXTERNAL_NET 53 -> $HOME_NET any (msg:"x"; pcre:"/^..\\x81\\x80/"; sid:1;)'
    ) is None
    # Not anchored at the start.
    assert dns_header_words(
        'alert udp $EXTERNAL_NET 53 -> $HOME_NET any (msg:"x"; pcre:"/..\\x81\\x80/"; sid:1;)'
    ) is None
