# Technical MVP report generator

This module builds a GOST-like technical report from Wazuh JSON data. It is intended for diploma demonstration and for readable review of host security findings.

## Input

The generator accepts either one JSON file or a directory with JSON files:

- unified IS-conveyer findings, for example `unified-findings.json`;
- raw Wazuh vulnerability indexer hits with `_source.vulnerability` and `_source.package`;
- raw Wazuh SCA checks with `result`, `title`, `rules` or `checks`.

Sample input is stored in `report/samples/wazuh-mvp/unified-findings.json`.

## Commands

```bash
python scripts/generate-report.py --input report/samples/wazuh-mvp --output report/sample-technical-report.md --format md
python scripts/generate-report.py --input report/samples/wazuh-mvp --output report/sample-technical-report.html --format html
python scripts/generate-report.py --input report/samples/wazuh-mvp --output report/full-technical-report.html --format html --include-passed --include-raw-appendix --include-low
python scripts/generate-report.py --input report/samples/wazuh-mvp --output report/summary-technical-report.md --format md --summary-only --min-severity high
```

## Report Structure

The MVP report contains:

- title block with generation date, checked object, hosts, tool version and data source;
- general assessment information and limitations;
- methodology with separate classes for code vulnerabilities and configuration vulnerabilities;
- aggregated statistics by host, status and severity;
- grouped software vulnerability table;
- grouped configuration non-compliance table;
- remediation priorities sorted by severity and grouped by CVE/check;
- automatic conclusion;
- finding/passport appendix;
- optional raw JSON appendix.

## Finding/Passport Model

All results pass through one normalized passport-like object with these fields:

- finding identifier;
- vulnerability type;
- detection source;
- affected object;
- component;
- description;
- manifestation conditions;
- severity;
- possible impact;
- detection method;
- remediation;
- external references;
- status.

Package CVE records are classified as `уязвимость кода`. Wazuh SCA/configuration records are classified as `уязвимость конфигурации`.

## Filtering and Aggregation

By default, the MVP report excludes passed checks and findings below `medium` severity. Use:

- `--min-severity low` or `--include-low` to include low severity records;
- `--include-passed` to include passed checks in the main section;
- `--max-records N` to limit detailed rows;
- `--summary-only` to render a compact report;
- `--include-raw-appendix` to embed raw JSON payloads.

Package vulnerabilities are deduplicated by host/agent, package, version, architecture and CVE. Configuration findings are deduplicated by requirement, command and expected state.
