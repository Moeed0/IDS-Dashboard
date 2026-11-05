# Data

Only the combined JSON export reads these files, to add each rule's text
and documentation and each CVE's details to the alerts. The dashboard's
other screens work without them.

| File | What it is | Where it comes from |
|---|---|---|
| `json/rule_docs_preprocessed_by_sid.json` | Snort's 4,017 community rules, parsed, with a link to each one's documentation on snort.org | Kept in git (9 MB) |
| `lab/rules/ids_rules.db` | Every Snort and Suricata rule, parsed | Built from the engines' rules (below); not in git |
| `intel/intel.db` | CVEs (NVD), EPSS scores, CISA's known exploited vulnerabilities and MITRE ATT&CK | Built from downloads (below); not in git (1.6 GB) |

Build the rule index again after the engines' rules change:

```bash
PYTHONPATH=src .venv/bin/python src/ids/build_rule_index.py
```

Download the threat-intel sources and build the database from them: NVD's
CVE feeds, FIRST's EPSS scores, CISA's known exploited vulnerabilities and
MITRE ATT&CK. That is about 300 MB of downloads, into `intel/sources/`, and a
few minutes of building. An NVD year that hasn't changed since the last run
isn't downloaded again, and the old database is replaced only once the new
one is complete.

```bash
.venv/bin/python scripts/download_intel_sources.py --build
```

To build from files you already have, use
`scripts/import_offline_intelligence.py` (`--help` lists its options).
