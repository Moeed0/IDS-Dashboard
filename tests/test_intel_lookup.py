import json
import sqlite3

from scripts.import_offline_intelligence import add_rule_docs
from scripts.intel_lookup import enrich, lookup, named, prompt_text

TALOS_DOCS = {
    "31978": {
        "gid": "1", "sid": "31978", "rev": "5", "doc_found": "1",
        "msg": "OS-OTHER Bash CGI environment variable injection attempt",
        "doc_url": "https://www.snort.org/rule_docs/1-31978",
        "rule_category": "OS-OTHER -- Snort has detected traffic targeting other systems.",
        "rule_explanation": (
            "GNU Bash runs trailing strings.\n\nImpact:\nCVSS base score 9.8\n\n"
            "Details:\nGNU Bash runs trailing strings.\n\nEase of Attack:\nSimple."
        ),
        "what_to_look_for": "This rule alerts on Shellshock attempts",
        "rule_vulnerability": "Command Injection\n \n\n Unsafe input reaches a shell.",
        "cve_ids": "CVE-2014-6271, CVE-1999-0001",
        "mitre_id": "T1190",
        "contributors": "Talos. Generated from data supplied by the national vulnerability database",
    },
    # Talos has no page for it.
    "105": {"gid": 1, "sid": 105, "rev": 14, "doc_found": 0, "msg": "MALWARE-BACKDOOR"},
}
SURICATA_RULES = (
    'alert udp $HOME_NET [!1720,!5060,1024:] -> $EXTERNAL_NET [!1720,!5060,1024:] (msg:"ET MALWARE '
    'Possible Downadup/Conficker-C P2P encrypted traffic UDP Ping Packet (bit value 16)"; dsize:>19; '
    'byte_test:1, &, 16, 19; reference:url,mtc.sri.com/Conficker/addendumC/; classtype:trojan-activity; '
    'sid:2009208; rev:4; metadata:created_at 2010_07_30, confidence Medium, signature_severity Major, '
    'updated_at 2019_07_26;)\n'
    '# alert tcp any any -> any any (msg:"ET INFO switched off"; sid:2000001; rev:1;)\n'
    'alert http any any -> any any (msg:"ET EXPLOIT Bash \\"Shellshock\\" attempt"; '
    'reference:cve,2014-6271; classtype:attempted-admin; priority:2; sid:2019232; rev:7; '
    'metadata:attack_target Web_Server, cve CVE_2014_6271, deployment Perimeter, '
    'mitre_tactic_id TA0001, mitre_tactic_name Initial_Access, mitre_technique_id T1190;)\n'
)
CLASSIFICATION = (
    "config classification: trojan-activity,A Network Trojan was detected,1\n"
    "config classification: attempted-admin,Attempted Administrator Privilege Gain,1\n"
)
# What snort --list-builtin, --help-modules-json and -V print.
FAKE_SNORT = """#!/bin/sh
case "$1" in
  --list-builtin) printf '116:414 (ipv4) IPv4 packet to broadcast dest address\\n122:23 (port_scan) UDP filtered portsweep\\n' ;;
  --help-modules-json) echo '[{"module": "ipv4", "type": "codec", "help": "support for Internet protocol v4"},
    {"module": "port_scan", "type": "inspector (probe)", "help": "detect various ip, icmp, tcp, and udp port or protocol scans"}]' ;;
  -V) echo '   o"  )~   Version 3.12.4.0' ;;
esac
"""


def _intel(tmp_path):
    path = tmp_path / "intel.db"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE source_metadata (source TEXT PRIMARY KEY, data_as_of TEXT,
            imported_at TEXT NOT NULL, version TEXT, record_count INTEGER NOT NULL DEFAULT 0,
            files_json TEXT NOT NULL DEFAULT '[]', sha256 TEXT);
        CREATE TABLE cves (cve_id TEXT PRIMARY KEY COLLATE NOCASE, description TEXT,
            published TEXT, cvss_score REAL, cvss_version TEXT, cvss_severity TEXT,
            cvss_vector TEXT, cwe_json TEXT);
        CREATE TABLE epss (cve_id TEXT PRIMARY KEY COLLATE NOCASE, score REAL,
            percentile REAL, score_date TEXT);
        CREATE TABLE kev (cve_id TEXT PRIMARY KEY COLLATE NOCASE, vendor_project TEXT,
            product TEXT, vulnerability_name TEXT, date_added TEXT, short_description TEXT,
            required_action TEXT, due_date TEXT, known_ransomware_campaign_use TEXT);
        CREATE TABLE attack_techniques (technique_id TEXT PRIMARY KEY COLLATE NOCASE,
            name TEXT, description TEXT, tactics_json TEXT, platforms_json TEXT);
        INSERT INTO source_metadata (source, data_as_of, imported_at, record_count)
            VALUES ('nvd', '2026-11-17T07:17:24', '2026-11-17T09:00', 1);
        INSERT INTO cves VALUES ('CVE-2014-6271', 'GNU Bash runs trailing strings.',
            '2014-09-24T18:48:04.477', 9.8, '3.1', 'CRITICAL', 'CVSS:3.1/AV:N', '["CWE-78"]');
        INSERT INTO epss VALUES ('CVE-2014-6271', 0.99999, 0.99993, '2026-11-16');
        INSERT INTO kev VALUES ('CVE-2014-6271', 'GNU', 'Bash', 'Shellshock', '2022-01-28',
            'Bash code injection.', 'Apply updates.', '2022-07-28', 'Known');
        INSERT INTO attack_techniques VALUES ('T1190', 'Exploit Public-Facing Application',
            'Adversaries may exploit a weakness.(Citation: X)

            More text.', '["initial-access"]', '["Linux"]');
        """
    )
    connection.commit()
    connection.close()
    docs = tmp_path / "docs.json"
    docs.write_text(json.dumps(TALOS_DOCS))
    # Pages download_talos_docs.py saved: one the local copy lacks, one with
    # no page (which leaves the local copy's alone).
    pages = tmp_path / "rule_docs.jsonl"
    pages.write_text("\n".join(json.dumps(page) for page in (
        {"gid": 3, "sid": 34051, "doc_found": 1, "msg": "PROTOCOL-DNS Cisco ASA",
         "rule_category": "PROTOCOL-DNS -- DNS issues.", "rule_explanation": "The ASA runs out of memory.",
         "mitre_id": "T1499, T1190"},
        {"gid": 1, "sid": 31978, "doc_found": 0},
    )) + "\n")
    stubs = tmp_path / "builtin_stubs.txt"
    stubs.write_text(
        "116:444\n\n(ipv4) IPv4 option set\n\n122:23\n\nFiltered one host to many hosts UDP portsweep\n"
        "where multiple ports are scanned\n\n"
    )
    rules = tmp_path / "suricata.rules"
    rules.write_text(SURICATA_RULES)
    local = tmp_path / "local.rules"
    local.write_text('alert icmp any any -> any any (msg:"LOCAL ICMP echo request (ping)"; itype:8; '
                     'classtype:misc-activity; sid:1000001; rev:1;)\n')
    classification = tmp_path / "classification.config"
    classification.write_text(CLASSIFICATION)
    snort = tmp_path / "snort"
    snort.write_text(FAKE_SNORT)
    snort.chmod(0o755)
    assert add_rule_docs(path, docs, pages, stubs, [rules, local], classification, str(snort))["counts"] == {
        "talos_rule_docs": 2, "snort_builtin_docs": 2, "snort_builtin_rules": 2, "suricata_rule_docs": 3,
    }
    return path


def test_rules_and_ids_are_found_in_each_way_a_file_writes_them():
    text = json.dumps({
        "rules": {"snort_signature:1:31978:5": {}, "suricata_signature:1:2019232:7": {}},
        "rule_text": 'alert tcp any any -> any any (msg:"x"; reference:cve,2014-6271;)',
        "metadata": {"cve": ["CVE_2019_12259"], "mitre_technique_id": ["T1190", "T1059.004"]},
        "msg": "ET EXPLOIT Possible CVE-2020-11899 read",
    })
    assert named(text) == {
        "rules": ["snort_signature:1:31978:5", "suricata_signature:1:2019232:7"],
        "cves": ["CVE-2014-6271", "CVE-2019-12259", "CVE-2020-11899"],
        "attack_techniques": ["T1059.004", "T1190"],
    }


def test_a_combined_file_is_enriched_with_talos_cves_and_techniques(tmp_path):
    db = _intel(tmp_path)
    combined = {"rules": {
        "snort_signature:1:31978:5": {"rule_text": "alert tcp any any -> any any (reference:cve,2014-6271;)"},
        "suricata_signature:1:2019232:7": {},
    }}
    combined["rules"].pop("suricata_signature:1:2019232:7")

    found = enrich(db, combined)

    talos = found["rules"]["snort_signature:1:31978:5"]["talos_documentation"]
    assert talos["description"] == "GNU Bash runs trailing strings."
    assert talos["ease_of_attack"] == "Simple."
    assert "details" not in talos  # it only repeats the description
    assert talos["vulnerability"] == {"type": "Command Injection", "description": "Unsafe input reaches a shell."}
    assert list(found["rules"]) == ["snort_signature:1:31978:5"]
    assert found["cves"]["CVE-2014-6271"]["cisa_kev"]["vulnerability_name"] == "Shellshock"
    # Named by the Talos documentation only.
    assert found["attack_techniques"]["T1190"]["description"] == "Adversaries may exploit a weakness."
    assert found["unknown"] == ["CVE-1999-0001"]
    assert found["sources"]["nvd"] == "2026-11-17"
    assert set(found["sources"]) == {
        "nvd", "talos_rule_docs", "snort_builtin_docs", "snort_builtin_rules", "suricata_rule_docs",
    }
    assert lookup(db, ["cve_2014_6271"])["cves"].keys() == {"CVE-2014-6271"}

    text = prompt_text(db, json.dumps(combined))
    assert text.startswith("Threat intelligence (NVD 2026-11-17, Talos rule documentation ")
    assert "Rule snort_signature:1:31978:5: Talos documentation\n  Category: OS-OTHER" in text
    # The description Talos copied from NVD is given once, with the CVE.
    assert text.count("GNU Bash runs trailing strings.") == 1
    assert "CVE-2014-6271 (published 2014-09-24)\n  Summary: GNU Bash runs trailing strings." in text
    assert "  CVSS 3.1: 9.8 CRITICAL (CVSS:3.1/AV:N)" in text
    assert "  CISA Known Exploited Vulnerability since 2022-01-28: Shellshock." in text
    assert "ATT&CK T1190: Exploit Public-Facing Application\n  Tactics: initial-access" in text
    assert text.endswith("Not in the database: CVE-1999-0001\n")


def test_downloaded_pages_and_builtin_descriptions_are_looked_up(tmp_path):
    db = _intel(tmp_path)

    found = lookup(db, ["snort_signature:3:34051:1", "snort_signature:122:23:1", "snort_signature:116:1:1"])

    assert found["rules"]["snort_signature:3:34051:1"]["talos_documentation"]["attack_techniques"] == [
        "T1499", "T1190",
    ]
    assert found["rules"]["snort_signature:122:23:1"]["snort_documentation"]["description"] == (
        "Filtered one host to many hosts UDP portsweep where multiple ports are scanned"
    )
    assert "snort_signature:116:1:1" not in found["rules"]
    text = prompt_text(db, "snort_signature:122:23:1")
    assert (
        "Rule snort_signature:122:23:1: Snort's description of this built-in rule\n"
        "  Message: UDP filtered portsweep\n"
        "  Description: Filtered one host to many hosts UDP portsweep where multiple ports are scanned\n"
        "  Raised by: Snort's port_scan inspector (detect various ip, icmp, tcp, and udp port or protocol "
        "scans): something that inspector watches for"
    ) in text


def test_a_builtin_decoder_rule_says_it_checks_the_packets_form(tmp_path):
    db = _intel(tmp_path)

    text = prompt_text(db, "snort_signature:116:414:1")

    assert (
        "Rule snort_signature:116:414:1: Snort's description of this built-in rule\n"
        "  Message: IPv4 packet to broadcast dest address\n"
        "  Raised by: Snort's packet decoder, ipv4 (support for Internet protocol v4), while reading the "
        "packet's headers: the packet is unusual or malformed for that protocol. This is a check on the "
        "packet's form, not a signature of a known attack, and it names no CVE.\n"
    ) in text


def test_a_suricata_rule_is_documented_from_its_own_text(tmp_path):
    db = _intel(tmp_path)

    found = lookup(db, ["suricata_signature:1:2009208:5", "suricata_signature:1:2019232:7"])

    assert found["rules"]["suricata_signature:1:2009208:5"] == {"suricata_rule": {
        "ruleset": "Emerging Threats Open",
        "message": "ET MALWARE Possible Downadup/Conficker-C P2P encrypted traffic UDP Ping Packet (bit value 16)",
        "category": "ET MALWARE",
        "class": {"name": "trojan-activity", "description": "A Network Trojan was detected", "priority": 1},
        "confidence": "Medium",
        "signature_severity": "Major",
        "created": "2010-07-30",
        "updated": "2019-07-26",
        "rev_in_database": 4,
        "references": ["mtc.sri.com/Conficker/addendumC/"],
    }}
    shellshock = found["rules"]["suricata_signature:1:2019232:7"]["suricata_rule"]
    assert shellshock["class"]["priority"] == 2  # the rule's own priority wins
    assert shellshock["message"] == 'ET EXPLOIT Bash "Shellshock" attempt'
    assert shellshock["attack_target"] == "Web Server"
    assert shellshock["attack_tactics"] == ["TA0001 Initial Access"]
    # Its CVE and technique are looked up too.
    assert set(found["cves"]) == {"CVE-2014-6271"}
    assert set(found["attack_techniques"]) == {"T1190"}

    text = prompt_text(db, "suricata_signature:1:2009208:4")
    assert (
        "Rule suricata_signature:1:2009208:4: the rule's own documentation (Emerging Threats Open)\n"
        "  Message: ET MALWARE Possible Downadup/Conficker-C P2P encrypted traffic UDP Ping Packet (bit value 16)\n"
        "  Category: ET MALWARE\n"
        "  Class: trojan-activity, A Network Trojan was detected (priority 1)\n"
        "  The rule's writers give it: confidence Medium, signature severity Major\n"
        "  Written 2010-07-30, last updated 2019-07-26\n"
        "  References: mtc.sri.com/Conficker/addendumC/\n"
    ) in text
    assert "Revision in the database" not in text


def test_a_rule_can_be_looked_up_by_its_sid_alone(tmp_path):
    db = _intel(tmp_path)

    found = lookup(db, ["2009208", "116:414", "1:2019232:7", "1000001", "999"])

    assert list(found["rules"]) == [
        "suricata_signature:1:2009208:4", "snort_signature:116:414:1",
        "suricata_signature:1:2019232:7", "suricata_signature:1:1000001:1",
    ]
    assert found["rules"]["suricata_signature:1:1000001:1"]["suricata_rule"]["ruleset"] == "Local rule of this lab"
    assert found["unknown"] == ["999"]
    # Commented out in the rules file: not loaded, not documented.
    assert lookup(db, ["2000001"])["unknown"] == ["2000001"]


def test_a_talos_page_is_read_into_the_local_copys_fields():
    from scripts.download_talos_docs import parse_page

    page = """<h1>x</h1><!-- TABBED CONTENT BEGIN -->
      <h3>Rule Category</h3><p>OS-OTHER -- Attacks on other systems.</p>
      <h3>Alert Message</h3><p>OS-OTHER Bash CGI environment variable injection attempt</p>
      <h3>Rule Explanation</h3><p class="rule-explanation">GNU Bash runs trailing strings.
Impact:
CVSS base score 10.0
Details:
Ease of Attack:
</p>
      <h3>What To Look For</h3><p>No information provided</p>
      <h3>Known Usage</h3><p>No public information</p>
      <h3>False Positives</h3><p>No known false positives</p>
      <h3>Contributors</h3><p>Cisco Talos Intelligence Group</p>
      <h3>Rule Groups</h3><p class="rg-fqn">MITRE::ATT&amp;CK Framework::Enterprise::Reconnaissance::Active Scanning</p>
        <p class="rg-description hidden">Adversaries scan.</p><p class="rg-mitre-id hidden">T1595</p>
      <h3 class="cve-header">CVE</h3><div><span class="cve-entry"><a href="#CVE-2014-6271">CVE-2014-6271</a></span>
        <span class="cve-entry"><a href="#CVE-2014-7169">CVE-2014-7169</a></span></div>
      <h3>Rule Vulnerability</h3><p class="rule_vulnerability">
              Command Injection
            </p><p class="rule_vulnerability_blurb">Unsafe input reaches a shell.</p>
      <h3>CVE Additional Information</h3><p>This product uses data from the NVD API</p>"""

    assert parse_page(page) == {
        "msg": "OS-OTHER Bash CGI environment variable injection attempt",
        "rule_category": "OS-OTHER -- Attacks on other systems.",
        "rule_explanation": "GNU Bash runs trailing strings.\nImpact:\nCVSS base score 10.0\nDetails:\nEase of Attack:",
        "what_to_look_for": "",
        "known_usage": "",
        "false_positives": "",
        "contributors": "Cisco Talos Intelligence Group",
        "rule_groups": "MITRE::ATT&CK Framework::Enterprise::Reconnaissance::Active Scanning",
        "mitre_id": "T1595",
        "cve_ids": "CVE-2014-6271, CVE-2014-7169",
        "rule_vulnerability": "Command Injection\nUnsafe input reaches a shell.",
    }


def test_a_page_refused_for_too_many_requests_is_fetched_again_after_waiting(monkeypatch):
    import email.message
    import io
    import urllib.error

    import scripts.download_talos_docs as talos

    answers = []

    def opened(request, timeout):
        answers.append(request.full_url)
        if len(answers) == 1:
            headers = email.message.Message()
            headers["Retry-After"] = "0"
            raise urllib.error.HTTPError(request.full_url, 429, "Too Many Requests", headers, io.BytesIO())
        return io.BytesIO(b'<!-- TABBED CONTENT BEGIN --><h3>Alert Message</h3><p>A rule</p>')

    monkeypatch.setattr(talos._opener, "open", opened)
    monkeypatch.setattr(talos, "_pace", talos._Pace())

    record = talos.fetch(1, 217)

    assert answers == ["https://www.snort.org/rule_docs/1-217"] * 2
    assert record == {
        "gid": 1, "sid": 217, "doc_found": 1,
        "doc_url": "https://www.snort.org/rule_docs/1-217", "msg": "A rule",
    }


def test_snort_orgs_address_is_looked_up_once_not_for_each_page(monkeypatch):
    import scripts.download_talos_docs as talos

    looked_up = []

    def lookup(host, *args, **kwargs):
        looked_up.append(host)
        return [("address of", host)]

    monkeypatch.setattr(talos, "_lookup", lookup)
    monkeypatch.setattr(talos, "_addresses", {})

    for _ in range(3):
        assert talos._remembered_lookup("www.snort.org", 443) == [("address of", "www.snort.org")]
    talos._remembered_lookup("example.org", 443)
    talos._remembered_lookup("example.org", 443)

    assert looked_up == ["www.snort.org", "example.org", "example.org"]
