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
    assert add_rule_docs(path, docs)["counts"] == {"talos_rule_docs": 1}
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

    found = enrich(db, combined)

    talos = found["rules"]["snort_signature:1:31978:5"]["talos_documentation"]
    assert talos["description"] == "GNU Bash runs trailing strings."
    assert talos["ease_of_attack"] == "Simple."
    assert "details" not in talos  # it only repeats the description
    assert talos["vulnerability"] == {"type": "Command Injection", "description": "Unsafe input reaches a shell."}
    assert list(found["rules"]) == ["snort_signature:1:31978:5"]  # ET Open has no docs
    assert found["cves"]["CVE-2014-6271"]["cisa_kev"]["vulnerability_name"] == "Shellshock"
    # Named by the Talos documentation only.
    assert found["attack_techniques"]["T1190"]["description"] == "Adversaries may exploit a weakness."
    assert found["unknown"] == ["CVE-1999-0001"]
    assert found["sources"]["nvd"] == "2026-11-17"
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
