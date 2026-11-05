# Data

Only the combined JSON export reads these files, to add each rule's text
and documentation and each CVE's details to the alerts. The dashboard's
other screens work without them.

| File | What it is | Where it comes from |
|---|---|---|
| `json/rule_docs_preprocessed_by_sid.json` | Snort's rule documentation, by SID | Kept in git (11 MB) |
| `lab/rules/ids_rules.db` | Every Snort and Suricata rule, parsed | Built from the engines' rules (below); not in git |
| `intel/intel.db` | CVEs (NVD), EPSS scores, CISA's known exploited vulnerabilities and MITRE ATT&CK | Built from downloads (below); not in git (1.6 GB) |

Build the rule index again after the engines' rules change:

```bash
PYTHONPATH=src .venv/bin/python src/ids/build_rule_index.py
```

Build the threat-intel database from downloaded copies of the NVD CVE
feeds, the EPSS scores, the CISA KEV list and the ATT&CK STIX bundle:

```bash
PYTHONPATH=src .venv/bin/python scripts/import_offline_intelligence.py --nvd-path <NVD files> --epss-csv <EPSS file> --kev-json <KEV file> --mitre-json <ATT&CK file> --replace
```
