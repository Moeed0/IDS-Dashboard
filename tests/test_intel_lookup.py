import json
import sqlite3

from scripts.intel_lookup import enrich, lookup, named_ids


def _intel(path):
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE source_metadata (source TEXT PRIMARY KEY, data_as_of TEXT,
            imported_at TEXT NOT NULL, record_count INTEGER);
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
        INSERT INTO source_metadata VALUES ('nvd', '2026-11-17', '2026-11-17T09:00', 1);
        INSERT INTO cves VALUES ('CVE-2014-6271', 'GNU Bash runs trailing strings.',
            '2014-09-24T18:48:04.477', 9.8, '3.1', 'CRITICAL', 'CVSS:3.1/AV:N', '["CWE-78"]');
        INSERT INTO epss VALUES ('CVE-2014-6271', 0.99999, 0.99993, '2026-11-16');
        INSERT INTO kev VALUES ('CVE-2014-6271', 'GNU', 'Bash', 'Shellshock', '2022-01-28',
            'Bash code injection.', 'Apply updates.', '2022-07-28', 'Known');
        INSERT INTO attack_techniques VALUES ('T1190', 'Exploit Public-Facing Application',
            'Adversaries may exploit.', '["initial-access"]', '["Linux"]');
        """
    )
    connection.commit()
    connection.close()
    return path


def test_ids_are_found_in_each_way_a_file_writes_them():
    text = json.dumps({
        "rule_text": 'alert tcp any any -> any any (msg:"x"; reference:cve,2014-6271;)',
        "metadata": {"cve": ["CVE_2019_12259"], "mitre_technique_id": ["T1190", "T1059.004"]},
        "msg": "ET EXPLOIT Possible CVE-2020-11899 read",
    })
    assert named_ids(text) == (
        ["CVE-2014-6271", "CVE-2019-12259", "CVE-2020-11899"], ["T1059.004", "T1190"],
    )


def test_a_combined_file_is_enriched_from_the_database(tmp_path):
    db = _intel(tmp_path / "intel.db")
    combined = tmp_path / "combined.json"
    combined.write_text(json.dumps({"rules": {"snort_signature:1:31978:5": {
        "rule_text": "alert tcp any any -> any any (reference:cve,2014-6271; reference:cve,1999-0001;)",
    }}, "x": "T1190"}))

    found = enrich(db, combined)

    assert found["cves"]["CVE-2014-6271"] == {
        "summary": "GNU Bash runs trailing strings.",
        "published": "2014-09-24",
        "cvss": {"score": 9.8, "version": "3.1", "severity": "CRITICAL", "vector": "CVSS:3.1/AV:N"},
        "cwe": ["CWE-78"],
        "epss": {"score": 0.99999, "percentile": 0.99993, "date": "2026-11-16"},
        "cisa_kev": {
            "vendor_project": "GNU", "product": "Bash", "vulnerability_name": "Shellshock",
            "date_added": "2022-01-28", "short_description": "Bash code injection.",
            "required_action": "Apply updates.", "due_date": "2022-07-28",
            "known_ransomware_campaign_use": "Known",
        },
    }
    assert found["attack_techniques"]["T1190"]["tactics"] == ["initial-access"]
    assert found["unknown"] == ["CVE-1999-0001"]
    assert found["sources"] == {"nvd": "2026-11-17"}
    assert lookup(db, ["cve_2014_6271"])["cves"].keys() == {"CVE-2014-6271"}
