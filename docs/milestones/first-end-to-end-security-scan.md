# first-end-to-end-security-scan

Milestone фиксирует первый воспроизводимый контур:

`Vagrant -> Ansible -> Wazuh Manager/Agent -> Findings export -> Unified JSON -> Draft Report`

## Критерии

- `wazuh`, `target1`, `target2` поднимаются через `Vagrant`
- manager и агенты доступны и активны
- `scripts/export-findings.py` формирует `artifacts/unified-findings.json`
- `scripts/generate-report.py` формирует `artifacts/draft-report.md`
- сценарий повторной проверки выполняется через `target_baseline_state=compliant`
