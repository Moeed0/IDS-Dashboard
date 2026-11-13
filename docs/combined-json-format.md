# Combined Snort + Suricata JSON (schema `ids.combined-detections` 9.3)

Built in the **Alert Explorer** from the alerts its filters choose ("Download
JSON", or "Send" to the LLM PC), or by the API for a whole time window (5
minutes to 7 days). The file is meant for analysis and LLM training. It is a
timeline of the packets the two engines alerted on, oldest first:

- a packet only Snort alerted on shows only Snort's part;
- a packet only Suricata alerted on shows only Suricata's part;
- a packet both engines alerted on is one entry with both parts, so what the
  packet is (time, protocol, addresses, ports) is written once.

Every alert in the window is kept with the IDS's own output, and values that
carry no information are left out. A file built from the Alert Explorer's
filters holds only the alerts they choose (a rule, a severity, an address,
the newest 20, …): its window then says when, and other alerts of that time
are not in it. Nothing is written twice (9.0):

- what is the same for every alert of a rule is given once in `rules`;
- what is the same for every alert of an engine on one connection is given
  once in `flows`;
- each CVE and ATT&CK technique is described once in `cves` and
  `attack_techniques`, however many rules name it;
- what says what the packet is is given once, with the packet, and so is
  what an engine's different alerts on one packet share (9.1);
- what a rule's name or rule text states is not repeated in its IDS output.

Each alert's whole record can be put back together exactly from these parts
(see The IDS output in parts). The file is indented with two spaces (9.2), so
it is laid out the same in every editor and browser; compact JSON was one long
line outside Firefox's JSON viewer, at about 0.55 times the size. The file holds no
classification, no general guidance and no summary counts beyond the alerts per
engine. This page replaces the `about` section that earlier versions repeated
in every file.

## Top level

| Key | Meaning |
|---|---|
| `window` | Start, end and length of the time window. Times are PKT (`+05:00`). The window ends where both engines' alerts are stored at the latest (see Window end). A file of the Alert Explorer's filters has the time range chosen, or with the newest N alerts (or no range) their own span in whole seconds (`"length": "104 seconds"`). |
| `alerts` | How many alerts each engine raised in the window; an engine that raised none is left out (`{"snort": 3}`). |
| `rules` | Each rule that fired in the window, once: its IDS output fields and its enrichment. |
| `cves` | Each CVE a rule names, once: NVD summary, CVSS, EPSS and CISA KEV. |
| `attack_techniques` | Each ATT&CK technique a rule names, once: name and tactics. |
| `flows` | Each connection with output the same on every alert of an engine on it, once, by number. |
| `packets` | The packets the engines alerted on, oldest first. |

`cves`, `attack_techniques` and `flows` are left out when they would be empty.

### Window end

The dashboard ends a window no later than where both engines' alerts are
stored: the last whole second before the older of the two engines' newest
stored alerts ("Latest complete time"; a chosen end time after it is moved
back to it, and the page says so).

One engine's newest alerts can reach the database after the other's: while it
or the collector restarts, or, until 5 November 2026, for up to a few minutes.
Before then Snort's default pcap DAQ read packets 64 at a time, so on this
quiet network it held its alerts until a group was full. Since then Snort reads
them with the afpacket DAQ and writes each alert within a second. A window
running into that time would show packets both engines alerted on as one
engine's only.

Each engine stores its alerts in time order (Suricata's worker threads a
fraction of a second apart at most, 0.14 s in the stored data), so every alert
before that time is stored. The second of the newest alert is left for a later
window, because one packet's alerts can be stored a moment apart.

## Packets

Both engines inspect every packet as it arrives and raise an alert on the
packet where a rule matches; neither waits for the connection to end. Each
entry in `packets` is one such packet:

- `packet` — its number, counted from 1 in time order across the file.
- `time` — when the packet was stamped; when both engines alerted on it, the
  earlier of their two stamps.
- `label` (9.3) — `lab attack` when the packet came from or went to a lab
  attacker (an `attacker_ip` of `config/lab_phases.json`), `background` for
  every other packet: what the alerts were raised on, for training and for
  checking a model. Left out of every packet when no attacker is listed.
- `protocol` — the packet's protocol. Snort calls IGMP `IP`, so a packet only
  Snort alerted on can say `IP`. Left out when no engine names one (Suricata's
  unknown-Ethertype events).
- `src`, `dst` — the packet's source and destination, as `address:port`
  (`[IPv6 address]:port`), or the address alone when the packet has no ports
  (ICMP, IGMP). IPv6 addresses are in their short form (Suricata writes them in
  full). Left out for frames without IP addresses (Snort's ARP checks).
- `icmp_type`, `icmp_code` — for ICMP packets.
- `flow` — the number, in `flows`, of the packet's connection, when `flows`
  holds something about it.
- `matched_by` — only on a packet both engines alerted on: how the two engines'
  alerts were found to be on this packet, `headers` or `time_and_addresses`
  (see Same packet).
- `ids_output` — only when an engine has more than one entry on the packet:
  per engine (`"suricata": {…}`), the output fields all its entries share,
  given once here instead of in each entry (9.1).
- `snort`, `suricata` — each engine's part, only when that engine alerted on
  the packet. It lists the engine's alerts on the packet as entries. Alerts
  whose output is the same apart from the rule (several rules firing on one
  packet) are one entry. An alert with a different output gets an entry of
  its own: for example Suricata's 2044666 names a target port that 2044665
  on the same packet does not, or one packet carries two HTTP transactions.
  Each entry has:
  - `rules` — the names, in `rules`, of the rules that fired.
  - `time` — the engine's own stamp, only when it differs from the packet's
    `time` (the engines stamp the same packet 0–50 µs apart).
  - `ids_output` — what is left of the engine's output for this packet once
    the rule's, the flow's and the packet's parts are taken out (see The IDS
    output in parts): mostly what changes from packet to packet, such as
    Snort's packet and byte counts so far, Suricata's `flow` counts, and HTTP
    or DNS details.

### Flows

A connection is one protocol between the same two endpoints (addresses and
ports), either way. `flows` holds, for each such connection and each engine
that alerted on more than one of its packets, the output fields with the same
value on every one of that engine's alerts on it: for example Suricata's
`community_id`, `app_proto`, `direction` and flow start, and Snort's
`flowstart_time`. Packets of the connection name it in `flow`. The timeline
is not grouped by connection; `flows` is a lookup, like `rules`.

### Same packet

A Snort and a Suricata alert are on the same packet when:

- their times are at most 100 µs apart (on live traffic each engine stamps the
  packet itself, 0–50 µs apart),
- they name the same packet source and destination (addresses, and ports or
  ICMP type and code when both engines report them), and
- the IP ID, TCP sequence and acknowledgement numbers, and ICMP identifier and
  sequence agree wherever both engines give them. Snort writes these values in
  its alert; Suricata's are read from the raw packet it writes in eve's alert
  `packet` (turned on 2 Nov 2026 at 11:48; earlier alerts have none). The raw
  packet itself is not part of `ids_output`.

`matched_by` says `headers` when such header values were compared, and
`time_and_addresses` when the engines gave none in common: Snort alerts on a
reassembled TCP segment (`pkt_gen: stream_tcp`) have no header values of their
own, IPv6 has no IP ID, and Suricata alerts from before 2 Nov 11:48 have no raw
packet.

Each packet pairs with at most one packet of the other engine, the closest in
time first. The engines' direction labels (`dir`, `direction`) are not
compared: each labels direction against its own idea of which side started the
flow, and for ICMP they disagree. Alerts without IP addresses (Snort's ARP
checks, Suricata's unknown-Ethertype events) are never combined: nothing ties
one engine's frames to the other's.

Within one engine, alerts are on the same packet when Snort gives them the same
packet number (`pkt_num`) and time (the number starts again when Snort
restarts), or Suricata the same time and raw packet.

### The IDS output in parts

Each alert's whole record, as the engine wrote it (less the fields listed
under What is left out), is these parts put together:

1. the rule's `ids_output` in `rules`: the fields that describe the rule
   (Snort `msg`, `class`, `priority`, `rev`; Suricata `alert.signature`,
   `category`, `severity`, `rev`, `metadata`) when they have one value on
   every alert of that rule in the file, and any other field with one value
   on every alert of that rule when it fired on more than one packet. Such a
   field moves to the rule only when every other rule in an entry with it
   moves it too; otherwise the entry would split in two and repeat what is
   left (9.1). A rule that fired on one packet moves what the other rules of
   its entry move;
2. the flow's part in `flows`, under the packet's `flow` and the engine's
   name (see Flows);
3. the packet's shared part, `ids_output` under the engine's name on the
   packet, when the engine has more than one entry there;
4. the entry's own `ids_output`: everything else;
5. what the rule's name and rule text state: the SID, the GID when it is not
   1, the revision (from a `:revN` name or the rule text's `rev`), the
   message (the rule text's `msg`), and Snort's `rule` field, which is
   `gid:sid:rev`. Each is left out of the rule's `ids_output` only when it
   says exactly the same;
6. the packet's fields, under the engine's own names: Snort `proto`,
   `src_addr`, `src_port`, `dst_addr`, `dst_port`, `icmp_type`, `icmp_code`;
   Suricata `proto`, `src_ip`, `src_port`, `dest_ip`, `dest_port`, `icmp_type`,
   `icmp_code`, and in its `flow` block `src_ip`, `src_port`, `dest_ip`,
   `dest_port` (the packet's source and destination, swapped when
   `direction` is `to_client`). Such a field is left out when it says the
   same as the packet; Suricata's `proto: "IPv6-ICMP"` is the packet's
   `ICMPv6`. A value that differs stays, such as Snort's `proto: "IP"` for
   IGMP.

The parts never hold the same field twice, so they can be merged key by key
(inside `alert` and `flow` too). `ids.combined_detections.rebuild_ids_output`
does this; the tests and a check on the live data (every alert of a 5-minute,
1-hour and 24-hour window and of the lab attack replay) rebuild each alert's
record exactly, with IPv6 addresses in their short form.

## Rules

`rules` holds each rule that fired in the window once, by the name its
alerts give: `engine:sid`, with the GID when it is not the default 1
(`snort:116:408`, a Snort built-in rule), and with the revision when one rule
fired with two revisions in the window (`snort:31978:rev5`). A rule appears
only when the file has something to say about it. Each rule has its
`ids_output` part (see The IDS output in parts) and the enrichment from
the local rule files and offline intelligence:

- `why_triggered` — what the rule looks for, in words with no backslashes
  (9.2), so that it reads the same in every editor and browser: a byte that is
  not plain text is written as `0x81`, a content match as its bytes and text
  (`` the bytes 0x0d 0x0a followed by `Host: ` ``), and a regular expression step
  by step (`at the start, any 2 bytes other than 0x0a, then a byte from 0x81
  to 0x87, then the byte 0x85`). A regular expression that cannot be worded
  exactly (PCRE-only syntax, or words over 1,000 characters) is "the regular
  expression in the rule text". `rule_text` keeps every pattern as written.
  Snort's built-in rules (GID above 1) have no rule text; their message names
  the check that failed.
- `rule_text` — the rule as written in the local Snort or Suricata rule
  file, without its web-link and CVE references (`reference:url,…`,
  `reference:cve,…`; the CVEs are the rule's `cves`) and its `metadata`
  option (rule upkeep or policy information, or a repeat of Suricata's own
  alert metadata). Every other option stays as written; a link inside a
  content match is detection logic and stays.
- `documentation` — the rule's published documentation, each part on one
  line: `description`, `impact`, `details`, `ease_of_attack`,
  `what_to_look_for` and `vulnerability` (`type` and `description`). Talos
  documents many Snort rules (4,017 in the local copy); Suricata's ET Open
  rules have none. Talos writes the documentation of many CVE rules from NVD
  data: a description or impact that copies a CVE's NVD summary or CVSS
  scores is left out (it is given under `cves`), and so are details that
  only repeat the description and impact. Added in 8.1.
- `what_it_means` — other rule-specific meaning (left out when it would
  only list the rule's CVEs or repeat the documented vulnerability type).
- `known_usage`, `false_positives` — from the rule's documentation.
- `what_to_check`, `recommended_actions` — rule-specific steps.
- `cves` — the IDs of the CVEs the rule names; their details are in the
  file's `cves`.
- `attack_techniques` — the IDs of the rule's ATT&CK techniques; their
  details are in the file's `attack_techniques`.

## CVEs and ATT&CK techniques

`cves` gives each CVE once, by ID: NVD `summary`, `cvss` (score, version,
severity, vector), `epss` (score, percentile) and `cisa_kev` (date added, and
`known_ransomware_use` when CISA lists it). `attack_techniques` gives each
technique once, by ID: `name` and `tactics`. A CVE with no local details is
named by its rules only.

## What is left out, and why

- Sentences that hold for any alert, or for every rule of a kind (for example
  "review surrounding IDS alerts and host logs", "verify whether the
  destination runs an affected product", "built-in rules have no rule text"):
  they say nothing about the alert at hand. The "check the documented false
  positives" step is left out too; the rule's own `false_positives` text says
  what they are.
- Recommended actions built only from a rule's CVE scores ("Check this
  destination first: CVE-… scores …"): `cves` gives the CVE and its scores.
- The generator ID when it is the default GID 1, and Snort's `rule` field
  (`gid:sid:rev`) with it.
- The packet action while it only says the packet passed (`allow` /
  `allowed`); both engines only watch a copy of the traffic. A blocking action
  would be kept.
- `pkt_src: "wire/pcap"` (a normal captured packet), Snort `service: "unknown"`
  and Suricata `app_proto: "failed"` (not identified), and Suricata `ip_v`.
- The engine's own timestamp field, which `time` states.
- DNS bookkeeping: transaction IDs, header flags, opcode and the log format
  version. The query names, record types, type and result code stay.
- Suricata rule metadata about rule upkeep and placement: creation, update and
  review dates, performance impact, deployment, former category, and
  `affected_product: Any`.
- Web links, interface names, MAC addresses, internal counters (`pkt_num`,
  `flow_id`, `tx_id`) and empty values.
- From a rule's documentation: its contributors, category text and
  reference lists, and the vulnerability type "N/A".

Kept as traffic evidence: the HTTP request path, HTTP headers such as an attack
payload, host and query names, and (9.3) what the packet carried as text:
Suricata's `payload_printable` and `http.http_request_body_printable` /
`http_response_body_printable` (on since 12 November 2026), and Snort's
`b64_data` given the same way, as `payload_printable` (printable ASCII, tabs
and line breaks kept, any other byte a dot). Suricata's Base64 `payload` and
`packet` are left out, as is Snort's `b64_data` itself: so Snort's record
rebuilds with `payload_printable` in place of `b64_data`.

## What can still look repeated

- Values of different packets that happen to be equal, such as a packet count
  of 1 on two one-packet connections, or the same TTL on packets of different
  rules. Each belongs to its own packet.
- The same values in the `ids_output` of rules that fire on the same kind of
  packet, such as `dir`, `pkt_gen`, `pkt_len` and `ttl` in Snort's 116:408,
  116:444 and 51037 (IGMP queries): each says what every alert of that rule
  had.
- A CVE named in a rule's message or in Suricata's own alert metadata
  (`cve: ["CVE_2014_6271"]`) as well as in the rule's `cves`: the message and
  metadata are the engine's own words, kept so each alert rebuilds exactly.
- The `rule_text` keeps the rule's own `sid` option, which the rule's name
  also gives: the rule text is kept as the rule is written.
