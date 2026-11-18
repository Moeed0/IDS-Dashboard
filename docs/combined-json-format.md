# Combined Snort + Suricata JSON (schema `ids.combined-detections` 14.0)

Built in the **Alert Explorer** from the alerts its filters choose ("Download
JSON", or "Send" to the LLM PC), or by the API for a whole time window (5
minutes to 7 days). The file is meant for analysis and LLM training. It is a
timeline of the packets the two engines alerted on, oldest first:

- a packet only Snort alerted on shows only Snort's part;
- a packet only Suricata alerted on shows only Suricata's part;
- a packet both engines alerted on is one entry with both parts, so what the
  packet is (time, protocol, addresses, ports) is written once.

Every alert in the window is kept with the IDS's whole output, exactly as the
engine wrote it (10.0): every field, in the engine's own spelling, with its
interface, MAC addresses, counters, IDs, links and empty values. A file built from the Alert Explorer's
filters holds only the alerts they choose (a rule, a severity, an address,
the newest 20, …): its window then says when, and other alerts of that time
are not in it. Nothing is written twice (9.0):

- what every one of an engine's alerts in the file has with the same value
  (its capture interface, the pass action, the event type) is given once, in
  the top-level `ids_output` (13.0; 10.1 to 12.0 took each field's most
  common value, which hid a rule's details there and needed `null` for the
  alerts without it);
- what describes a rule (message, class or category, priority or severity,
  metadata) is always in that rule's entry in `rules`, even when every alert
  shares it, so each rule's entry says everything about the rule (13.0), and
  anything else the same for every alert of a rule is given there once;
- what is the same for every alert of an engine on one connection is given
  once in `flows`;
- what says what the packet is is given once, with the packet, and so is
  what an engine's different alerts on one packet share (9.1);
- what a rule's name states (GID, SID, revision) is not repeated in its IDS
  output;
- what the alert's time and Suricata's raw packet already say (the engine's
  `timestamp`, Suricata's `payload_printable`) is derived from them, not
  written again (10.0).

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
| `ids_output` | Per engine: the output fields every one of its alerts in the file has with the same value, given once (`{"snort": {"iface": "ens34", …}}`, 13.0). Never a rule's details: those are in `rules`. See The IDS output in parts. |
| `rules` | Each rule that fired in the window, once: its IDS output fields and its rule text. |
| `flows` | Each connection with output the same on every alert of an engine on it, once, by number. |
| `packets` | The packets the engines alerted on, oldest first. |

`flows` is left out when it would be empty.

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
- (9.4) No `label`: 9.3's `lab attack` / `background` for each packet was
  removed on 13 November 2026, at the user's request.
- `protocol` — the packet's protocol. Snort calls IGMP `IP`, so a packet only
  Snort alerted on can say `IP`. Left out when no engine names one (Suricata's
  unknown-Ethertype events).
- `src`, `dst` — the packet's source and destination, as `address:port`
  (`[IPv6 address]:port`), or the address alone when the packet has no ports
  (ICMP, IGMP). IPv6 addresses are in their short form; Suricata writes them
  in full, and its record rebuilds that way. Left out for frames without IP addresses (Snort's ARP checks).
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
  `packet` (turned on 2 Nov 2026 at 11:48; earlier alerts have none;
  `deploy/apply-suricata-settings.sh` turns it on since 17 Nov 2026). The raw
  packet is part of Suricata's `ids_output` (10.0).

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

Each alert's whole record, exactly as the engine wrote it, is these parts put
together:

1. what the engine's alerts all share, in the file's top-level `ids_output`
   (13.0): a field every one of the engine's alerts has, with the same value.
   Never what describes a rule (part 2), a rule's identity, the `timestamp`
   or `payload_printable`;
2. the rule's `ids_output` in `rules`: the fields that describe the rule
   (Snort `msg`, `class`, `priority`, `gid`, `rev`, `rule`; Suricata
   `alert.signature`, `category`, `severity`, `gid`, `rev`, `metadata`) when
   they have one value on every alert of that rule in the file, and any other
   field with one value on every alert of that rule when it fired on more
   than one packet. Such a field moves to the rule only when every other rule
   in an entry with it moves it too; otherwise the entry would split in two
   and repeat what is left (9.1). A rule that fired on one packet moves what
   the other rules of its entry move;
3. the flow's part in `flows`, under the packet's `flow` and the engine's
   name (see Flows);
4. the packet's shared part, `ids_output` under the engine's name on the
   packet, when the engine has more than one entry there;
5. the entry's own `ids_output`: everything else;
6. what the rule's name states (11.0): the GID, SID and revision of
   `snort_signature:GID:SID:REV` or `suricata_signature:GID:SID:REV`, and
   Snort's `rule` field, which is `gid:sid:rev`. Each is left out of the
   rule's `ids_output` only when it says exactly the same. So is the
   message (Snort `msg`, Suricata `alert.signature`) when the rule text's
   `msg` says exactly the same;
7. the packet's fields, under the engine's own names and in its own
   spelling: Snort `proto`, `src_addr`, `src_port`, `dst_addr`, `dst_port`,
   `icmp_type`, `icmp_code`; Suricata `proto`, `src_ip`, `src_port`,
   `dest_ip`, `dest_port`, `icmp_type`, `icmp_code`, and in its `flow` block
   `src_ip`, `src_port`, `dest_ip`, `dest_port` (the packet's source and
   destination, swapped when `direction` is `to_client`). Suricata writes
   IPv6 in full (`ff02:0000:0000:0000:0000:0000:0000:0016`) and calls ICMPv6
   `IPv6-ICMP`. Such a field is left out when it says exactly what the
   packet does in that spelling; a value that differs stays, such as Snort's
   `proto: "IP"` for IGMP;
8. what the alert's time and Suricata's raw packet say (10.0):
   - `timestamp` — the entry's `time` (or the packet's) in the engine's own
     format, in local time (PKT): Snort `MM/DD-HH:MM:SS.ffffff`
     (`11/17-13:38:07.235708`), Suricata ISO 8601 with a `+0500` offset;
   - Suricata's `payload_printable` — the payload of its raw `packet` (after
     the TCP, UDP or ICMP header, up to the IP length) as text: printable
     ASCII, tabs and line breaks kept, any other byte a dot. When Suricata
     wrote none for a packet that carries a payload, the entry says
     `"payload_printable": null`, the only null in the IDS output, which
     the rebuild removes.

   Each is left out only when the derived value is exactly the one the
   engine wrote; otherwise it stays, such as Suricata's text of reassembled
   stream data, which is not the packet's own payload.

Parts 1 to 5 never hold the same field twice. So they are merged key by key
(inside `alert` and `flow` too). `ids.combined_detections.rebuild_ids_output`
does this; the tests and a check on the live data (the newest 3,000 alerts
on 18 Nov 2026, with 13.0) rebuild each alert's record exactly as the engine
wrote it. The IDS output has no `null` but Suricata's `payload_printable`
one (part 8).

## Rules

`rules` holds each rule that fired in the window once, by the name its
alerts give, in one format for both engines (11.0):
`snort_signature:GID:SID:REV` and `suricata_signature:GID:SID:REV`, such as
`snort_signature:116:408:1` (a Snort built-in rule),
`snort_signature:1:31978:5` and `suricata_signature:1:2001119:6`. Two
revisions of one rule are two rules. A rule appears
only when the file has something to say about it. Each rule has

- `severity` (14.0): the engine's severity in words, `Critical` (1, the most
  severe), `Medium` (2), `Low` (3) or `Info` (4): Snort's `priority`,
  Suricata's `alert.severity`, which stay as numbers in `ids_output`. Not
  Suricata's `metadata.signature_severity`, the rule author's own label
  (Critical, Major, Minor, Informational), which Snort's rules don't have;
- `detection` (14.0): what the rule looks for, in plain words, read from its
  rule text: the ports and addresses it checks, its flow, ICMP type and
  code, the numbers it tests in words (`ip_proto:!17` is "the IP protocol
  is not 17 (UDP)", `flags:S,12` "the TCP flags are exactly SYN (ignoring
  CWR and ECE)", `dsize:>100` "the payload size is more than 100 bytes";
  also ttl, window, ack, seq, id, tos, fragbits, fragoffset, ipopts,
  urilen, stream_size, sameip, icmp_id and icmp_seq), and each content and
  pcre pattern read out with no backslashes
  (text as text, other bytes as 0x81, a regular expression step by step:
  `pcre:"/^..[\x81\x82\x83\x84\x85\x86\x87]\x85/"` becomes "at the start, any
  2 bytes other than 0x0a, then a byte from 0x81 to 0x87, then the byte
  0x85"). Up to six patterns are read out. A UDP rule on port 53 whose
  patterns fix bytes at the start of the DNS message also gets what those
  bytes mean in the DNS header (RFC 1035, `ids/dns_header_words.py`):
  2001119's adds "byte 3 (0x81 to 0x87) means a response (QR=1) to a
  standard query (opcode 0, QUERY), with at least one of AA, TC or RD set;
  byte 4 (0x85) means RA set, …, response code 5, Refused" (164 of the
  loaded rules). A Snort built-in rule (GID above
  1) has no rule text: its `detection` is Snort's own description of the
  rule, from intel.db's `snort_builtin_docs` ("A built-in Snort rule
  (116:408), with no rule text. Snort's own description of what it
  detects: The IPv4 packet's source address is from the 'current net'
  (value of zero)");
- its `ids_output` part (see The IDS output in parts);
- its `rule_text`: the rule as written in the local Snort or Suricata rule
  file, its regular expressions' bytes written by value, `\x81` as `0x81`
  (with a space between such bytes; a letter, digit or plain sign as
  itself): `pcre:"/^..[\x81\x82\x83\x84\x85\x86\x87]\x85/"` reads
  `pcre:"/^..[0x81 0x82 0x83 0x84 0x85 0x86 0x87]0x85/"`. The message,
  content matches and other options stay as written. The file's
  `detection` says what the pattern matches. Also without

- its `sid`, `gid` and `rev` options, which the rule's name gives (11.1);
- its `classtype`, which the alert's `class` (Snort) or `category`
  (Suricata) gives (12.0);
- its `metadata` option (rule upkeep or policy information, or a repeat of
  Suricata's own alert metadata);
- its web-link references (`reference:url,…`).

Every other option stays as written, the CVE references
(`reference:cve,2014-6271`) among them; a link inside a content match is
detection logic and stays. Snort's built-in rules (GID above 1) have no rule
text; their message names the check that failed (`(ipv4) IPv4 option set`:
the `ipv4` decoder).

## No enrichment (12.0)

The file holds the alerts and nothing else: no explanation of the rules
(`why_triggered`), no published rule documentation, no CVE or ATT&CK
details, no advice. Until 11.1 it carried them; now the LLM adds them
itself, from the same threat-intelligence database, which the dashboard
offers at `/intel/intel.db` (about 1.4 GB: NVD, EPSS, CISA KEV and MITRE
ATT&CK; `/intel` says what each source's data is as of).

The database also holds the Snort rules' documentation, all of it read
from files on the IDS machine:

- `talos_rule_docs`: Talos's documentation, by GID and SID. It comes from the
  local copy `data/json/rule_docs_preprocessed_by_sid.json` (3,945 rules),
  and from `data/intel/sources/talos/rule_docs.jsonl`, where
  `scripts/download_talos_docs.py` saves the snort.org page of every rule in
  the registered snapshot (about 52,700 text and SO rules; the 4,017 the
  local copy has are skipped) once, one page at a time at the pace
  snort.org allows (a page every 3 seconds or so, so a day or two; it slows
  down when snort.org answers HTTP 429, and looks www.snort.org up once every
  half hour, since each lookup reaches the lab network and raises Suricata
  alerts).
  Run it once, again if it stops, and after a rule update to fetch only the
  new rules:

      .venv/bin/python scripts/download_talos_docs.py
      PYTHONPATH=src:scripts .venv/bin/python scripts/import_offline_intelligence.py --add-rule-docs

  Nothing reads snort.org after that: the database holds the pages.
- `snort_builtin_docs`: Snort's own description of each built-in rule
  (GID 2 and up, 638 rules), from `builtin_stubs.txt` in Snort's source,
  installed with it at `/usr/local/share/doc/snort/`.

ET Open's Suricata rules have no such documentation; a rule of your own
(`local.rules`) has none either.

On the LLM PC, `scripts/intel_lookup.py` (standard library only) fetches the
database and writes what it says of a file as plain text, to put in the
LLM's prompt:

    python intel_lookup.py download http://172.16.20.142:8501/
    python intel_lookup.py enrich snort_suricata_combined_….json
    python intel_lookup.py lookup snort_signature:1:31978:5 CVE-2014-6271 T1190

or, from a program, `prompt_text(db, combined_json)`. It finds every rule the
file names and the CVEs (a rule text's `reference:cve,2014-6271`, Suricata's
metadata `CVE_2014_6271`, a message's `CVE-2020-11899`) and ATT&CK
techniques (Suricata's `mitre_technique_id`) it names, plus those a rule's
Talos documentation names, and gives:

- a built-in Snort rule's description, from Snort;
- a Snort rule's Talos documentation: category (described once), description,
  impact, details, ease of attack, what to look for, false positives, known
  usage, vulnerability type, CVEs and technique; the parts that repeat
  another or copy a CVE's NVD summary or scores are left out;
- a CVE's NVD summary, publication date, CVSS, CWEs, EPSS and CISA KEV entry;
- a technique's name, tactics, platforms and description.

`--json` prints the same as JSON.

The dashboard's own alert view still shows the enrichment for a person
reading one alert.

## What is kept

Nothing of the engines' own output is left out (10.0; until 9.4 the
interface, MAC addresses, internal counters and IDs, the pass action,
default values, DNS bookkeeping, rule upkeep metadata, web links and empty
values were left out, so a record didn't rebuild exactly).

What the packet carried is the engines' own: Snort's `b64_data` and
Suricata's raw `packet`, in Base64, and Suricata's `payload_printable` and
`http.http_request_body_printable` / `http_response_body_printable` as text
(on since 12 November 2026). Suricata's `payload_printable` is derived from
its raw packet when it is that packet's payload (see The IDS output in
parts). 9.3 to 9.4 wrote Snort's `b64_data` as text instead; 10.0 keeps it as
Snort wrote it and adds no text copy.

Also kept: Snort's `app_id`, the application its OpenAppID detectors named
for the flow (`"IGMP"`, `"ICMP for IPv6"`, `"UPnP"`, `"NetBIOS-ns"` ...; on
since 12 November 2026, so older alerts have none). Like any field of
Snort's own output it is written once: in the rule's `ids_output` when all
the rule's alerts in the file share it, otherwise on each packet. Suricata
has no such field (its `app_proto`, the protocol it parsed, is the nearest).
The dashboard calls it "App" and filters by it.

## What can still look repeated

- A value most, but not all, of an engine's alerts share (a MAC address, a
  pcap file, a direction): only a value every alert shares is in the
  top-level `ids_output`, so the alerts with it each write it unless a rule,
  flow or packet holds it for them.
- A rule detail every rule shares (all severity 3, say): each rule's entry
  gives its own, so a rule's entry is complete.
- Values of different packets that happen to be equal, such as a packet count
  of 1 on two one-packet connections, or the same TTL on packets of different
  rules. Each belongs to its own packet.
- The same values in the `ids_output` of rules that fire on the same kind of
  packet, such as `dir`, `pkt_gen`, `pkt_len` and `ttl` in Snort's 116:408,
  116:444 and 51037 (IGMP queries): each says what every alert of that rule
  had.
- A CVE named in a rule's message or in Suricata's own alert metadata
  (`cve: ["CVE_2014_6271"]`) as well as in its rule text's
  `reference:cve,…`: the message and metadata are the engine's own words,
  kept so each alert rebuilds exactly, and the rule text is the rule's.
