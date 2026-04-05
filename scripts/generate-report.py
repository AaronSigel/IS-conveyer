#!/usr/bin/env python3
import argparse
import json
import pathlib
from collections import Counter, defaultdict
from datetime import datetime, timezone


PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_INPUT = PROJECT_ROOT / "artifacts" / "unified-findings.json"
DEFAULT_OUTPUT = PROJECT_ROOT / "artifacts" / "draft-report.md"
TEMPLATE_PATH = PROJECT_ROOT / "report" / "templates" / "report-template.md"


def load_findings(path):
    return json.loads(path.read_text(encoding="utf-8"))


def recommendation_block(findings):
    remediations = []
    seen = set()
    for item in findings:
        if item["status"] != "fail":
            continue
        key = (item["rule_id"], item["remediation"])
        if key in seen:
            continue
        seen.add(key)
        remediations.append(f"- `{item['rule_id']}`: {item['remediation']}")
    return "\n".join(remediations) if remediations else "- Существенных отклонений не выявлено."


def summary_conclusion(findings):
    total = len(findings)
    failed = sum(1 for item in findings if item["status"] == "fail")
    passed = sum(1 for item in findings if item["status"] == "pass")
    if failed:
        return (
            f"Выявлено {failed} отклонений из {total} проверок. "
            f"После исправления следует выполнить повторный экспорт findings и повторную генерацию отчёта."
        )
    return f"Все {passed} проверки из {total} завершились со статусом PASS."


def render_report(findings):
    now = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    by_host = defaultdict(list)
    for finding in findings:
        by_host[finding["host"]].append(finding)
    hosts = sorted(by_host)

    host_lines = []
    table_lines = ["| Хост | Категория | Правило | Статус | Критичность | Доказательства |", "| --- | --- | --- | --- | --- | --- |"]
    for host in hosts:
        counts = Counter(item["status"] for item in by_host[host])
        host_lines.append(f"- `{host}`: fail={counts.get('fail', 0)}, pass={counts.get('pass', 0)}")
        for item in by_host[host]:
            evidence = "<br>".join(item["evidence"])
            table_lines.append(
                f"| {host} | {item['category']} | `{item['rule_id']}` | {item['status'].upper()} | {item['severity']} | {evidence} |"
            )

    methods = [
        "- Регистрация и транспорт событий подтверждаются через Wazuh manager и active agents.",
        "- Конфигурационные findings берутся из Wazuh API по SCA policy `host-baseline-v1`.",
        "- Findings по уязвимым пакетам берутся из `Wazuh indexer` (`wazuh-states-vulnerabilities*`).",
        "- Инвентаризационный контекст по хостам берётся из Wazuh API /syscollector.",
        "- Шумовые operational данные сохраняются отдельно как raw API artifact и не включаются в итоговый отчёт.",
    ]

    report = TEMPLATE_PATH.read_text(encoding="utf-8")
    report += "\n\n"
    report += "## Заполненный Черновик\n\n"
    report += f"- Дата: {now}\n"
    report += f"- Объект проверки: {', '.join(f'`{host}`' for host in hosts)}\n"
    report += f"- Состав стенда: `wazuh`, {', '.join(f'`{host}`' for host in hosts)}\n"
    report += "- Используемый профиль: `host-baseline-v1`\n\n"
    report += "## Методика Выполнения\n\n"
    report += "\n".join(methods) + "\n\n"
    report += "## Сводка По Хостам\n\n"
    report += "\n".join(host_lines) + "\n\n"
    report += "## Нормализованные Findings\n\n"
    report += "\n".join(table_lines) + "\n\n"
    report += "## Рекомендации По Исправлению\n\n"
    report += recommendation_block(findings) + "\n\n"
    report += "## Итоговое Заключение\n\n"
    report += summary_conclusion(findings) + "\n"
    return report


def main():
    parser = argparse.ArgumentParser(description="Generate a draft markdown report from unified findings.")
    parser.add_argument("--input", default=str(DEFAULT_INPUT))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    args = parser.parse_args()

    input_path = pathlib.Path(args.input)
    output_path = pathlib.Path(args.output)
    findings = load_findings(input_path)
    output_path.write_text(render_report(findings), encoding="utf-8")
    print(f"Draft report written to {output_path}")


if __name__ == "__main__":
    main()
