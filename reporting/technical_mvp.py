from __future__ import annotations

import json
import logging
import pathlib
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from reporting.aggregation.deduplicate import deduplicate_findings
from reporting.aggregation.severity import calculate_priority
from reporting.builder import normalize_finding
from reporting.common import severity_rank
from reporting.normalizers.wazuh_sca import normalize_sca_findings
from reporting.normalizers.wazuh_vulnerabilities import normalize_vulnerability_findings

LOG = logging.getLogger(__name__)
PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
TEMPLATES_DIR = pathlib.Path(__file__).resolve().parent / "templates"
NO_DATA = "нет данных"
SEVERITIES = ("critical", "high", "medium", "low", "info")
STATUSES = ("fail", "pass", "not_applicable", "unknown")


@dataclass(frozen=True)
class ReportOptions:
    min_severity: str = "medium"
    include_low: bool = False
    include_passed: bool = False
    include_raw_appendix: bool = False
    max_records: int = 200
    summary_only: bool = False
    source_name: str = "Wazuh JSON"
    system_name: str = "Проверяемая информационная система"
    tool_version: str = "IS-conveyer technical MVP"


def _read_json(path: pathlib.Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _iter_json_files(path: pathlib.Path) -> list[pathlib.Path]:
    if path.is_file():
        return [path]
    return sorted(item for item in path.rglob("*.json") if item.is_file())


def _as_items(payload: Any) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for keys in (("hits", "hits"), ("data", "affected_items"), ("data", "items"), ("items",), ("findings",), ("checks",)):
            current: Any = payload
            for key in keys:
                current = current.get(key) if isinstance(current, dict) else None
            if isinstance(current, list):
                return current
        return [payload]
    return []


def _looks_like_unified_finding(item: Any) -> bool:
    return isinstance(item, dict) and (
        item.get("finding_type")
        or item.get("wazuh_sca")
        or item.get("wazuh_vulnerability")
        or (item.get("category") in {"configuration", "vulnerability"} and item.get("host"))
    )


def _looks_like_vulnerability_hit(item: Any) -> bool:
    source = item.get("_source") if isinstance(item, dict) else None
    return isinstance(source, dict) and isinstance(source.get("vulnerability"), dict) and isinstance(source.get("package"), dict)


def _looks_like_sca_check(item: Any) -> bool:
    if not isinstance(item, dict):
        return False
    result = str(item.get("result") or item.get("status") or "").lower()
    return result in {"passed", "failed", "pass", "fail"} and (item.get("rules") or item.get("checks") or item.get("title"))


def _host_from_payload(payload: Any, fallback: str) -> str:
    if isinstance(payload, dict):
        for key in ("host", "hostname", "agent_name"):
            if payload.get(key):
                return str(payload[key])
        agent = payload.get("agent")
        if isinstance(agent, dict) and agent.get("name"):
            return str(agent["name"])
    return fallback


def load_wazuh_findings(input_path: str | pathlib.Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Load unified findings or raw Wazuh-like JSON snapshots from a file or directory."""
    root = pathlib.Path(input_path)
    raw_findings: list[dict[str, Any]] = []
    raw_appendix: list[dict[str, Any]] = []
    files = _iter_json_files(root)
    LOG.info("processing JSON files: %s", len(files))

    for file_path in files:
        payload = _read_json(file_path)
        items = _as_items(payload)
        raw_appendix.append({"file": str(file_path), "items": len(items), "payload": payload})

        unified = [item for item in items if _looks_like_unified_finding(item)]
        if unified:
            raw_findings.extend(unified)
            LOG.info("%s: loaded unified findings=%s", file_path, len(unified))
            continue

        vulnerability_hits = [item for item in items if _looks_like_vulnerability_hit(item)]
        if vulnerability_hits:
            targets = sorted({str(item["_source"].get("agent", {}).get("name")) for item in vulnerability_hits if item["_source"].get("agent", {}).get("name")})
            raw_findings.extend(normalize_vulnerability_findings(vulnerability_hits, tuple(targets), {}))
            LOG.info("%s: normalized vulnerability hits=%s", file_path, len(vulnerability_hits))
            continue

        sca_checks = [item for item in items if _looks_like_sca_check(item)]
        if sca_checks:
            host = _host_from_payload(payload, file_path.stem)
            agent = payload.get("agent") if isinstance(payload, dict) and isinstance(payload.get("agent"), dict) else {"name": host}
            host_os = payload.get("host_os") if isinstance(payload, dict) and isinstance(payload.get("host_os"), dict) else {}
            raw_findings.extend(normalize_sca_findings(host, sca_checks, agent=agent, host_os=host_os))
            LOG.info("%s: normalized SCA checks=%s", file_path, len(sca_checks))

    LOG.info("loaded raw findings: %s", len(raw_findings))
    return raw_findings, raw_appendix


def _status(value: Any) -> str:
    text = str(value or "unknown").strip().lower()
    return {"failed": "fail", "failure": "fail", "passed": "pass", "not applicable": "not_applicable", "n/a": "not_applicable"}.get(text, text)


def _severity(finding: dict[str, Any]) -> str:
    severity = finding.get("severity")
    if isinstance(severity, dict):
        return str(severity.get("level") or "info").lower()
    return str(severity or "info").lower()


def _host_names(findings: list[dict[str, Any]]) -> list[str]:
    hosts: set[str] = set()
    for finding in findings:
        hosts.update(str(item) for item in finding.get("affected_assets", []) or [] if item)
        if finding.get("host"):
            hosts.add(str(finding["host"]))
    return sorted(hosts)


def _asset_os(report_assets: list[dict[str, Any]], host: str) -> str:
    for asset in report_assets:
        if str(asset.get("agent.name")) == str(host):
            return str(asset.get("host.os.full") or asset.get("host.os.version") or NO_DATA)
    return NO_DATA


def _finding_passport(finding: dict[str, Any]) -> dict[str, Any]:
    finding_type = finding.get("type")
    package = finding.get("package") if isinstance(finding.get("package"), dict) else {}
    requirement = finding.get("requirement") if isinstance(finding.get("requirement"), dict) else {}
    check = finding.get("check") if isinstance(finding.get("check"), dict) else {}
    remediation = finding.get("remediation") if isinstance(finding.get("remediation"), dict) else {}
    detection = finding.get("detection") if isinstance(finding.get("detection"), dict) else {}
    vulnerability_type = "уязвимость кода" if finding_type == "software_vulnerability" else "уязвимость конфигурации"
    component = package.get("name") if finding_type == "software_vulnerability" else requirement.get("id")
    return {
        "id": finding.get("finding_uid") or NO_DATA,
        "type": vulnerability_type,
        "source": finding.get("source") or detection.get("source") or NO_DATA,
        "target_object": ", ".join(finding.get("affected_assets", []) or []) or NO_DATA,
        "component": component or NO_DATA,
        "description": finding.get("description") or finding.get("title") or NO_DATA,
        "conditions": package.get("fixed_condition") or check.get("command") or NO_DATA,
        "severity": _severity(finding),
        "impact": finding.get("impact") or "риск определяется классом найденной уязвимости и уровнем критичности",
        "detection_method": detection.get("scanner") or NO_DATA,
        "remediation": remediation.get("summary") or NO_DATA,
        "references": _unique_refs(finding.get("references")),
        "status": _status(finding.get("status")),
    }


def _unique_refs(value: Any) -> list[str]:
    refs: list[str] = []
    for item in value or []:
        text = str(item).strip()
        if text and text not in refs:
            refs.append(text)
    return refs


def _fixed_version(condition: Any) -> str:
    text = str(condition or "").strip()
    if not text or text == "not provided":
        return NO_DATA
    marker = "less than "
    lowered = text.lower()
    if marker in lowered:
        return text[lowered.rfind(marker) + len(marker) :].strip().rstrip(".")
    return text


def _software_row(finding: dict[str, Any], assets: list[dict[str, Any]]) -> dict[str, Any]:
    host = next(iter(finding.get("affected_assets", []) or [NO_DATA]))
    package = finding.get("package") if isinstance(finding.get("package"), dict) else {}
    severity = finding.get("severity") if isinstance(finding.get("severity"), dict) else {}
    detection = finding.get("detection") if isinstance(finding.get("detection"), dict) else {}
    return {
        "host_id": finding.get("asset_details", {}).get(host, {}).get("agent.id", NO_DATA),
        "host": host,
        "os": _asset_os(assets, host),
        "package": package.get("name") or NO_DATA,
        "installed_version": package.get("installed_version") or NO_DATA,
        "fixed_version": _fixed_version(package.get("fixed_condition")),
        "cve": finding.get("cve") or NO_DATA,
        "severity": severity.get("level") or "info",
        "cvss": severity.get("score") if severity.get("score") not in (None, -1) else NO_DATA,
        "description": finding.get("description") or NO_DATA,
        "source": detection.get("source") or finding.get("source") or NO_DATA,
        "references": _unique_refs(finding.get("references")),
        "status": _status(finding.get("status")),
    }


def _config_row(finding: dict[str, Any], assets: list[dict[str, Any]]) -> dict[str, Any]:
    host = next(iter(finding.get("affected_assets", []) or [NO_DATA]))
    requirement = finding.get("requirement") if isinstance(finding.get("requirement"), dict) else {}
    check = finding.get("check") if isinstance(finding.get("check"), dict) else {}
    remediation = finding.get("remediation") if isinstance(finding.get("remediation"), dict) else {}
    return {
        "host_id": finding.get("asset_details", {}).get(host, {}).get("agent.id", NO_DATA),
        "host": host,
        "check_id": requirement.get("id") or finding.get("finding_uid") or NO_DATA,
        "title": finding.get("title") or NO_DATA,
        "description": finding.get("description") or NO_DATA,
        "severity": _severity(finding),
        "actual": check.get("actual") or check.get("result") or _status(finding.get("status")),
        "expected": check.get("expected") or NO_DATA,
        "remediation": remediation.get("summary") or NO_DATA,
        "standard": requirement.get("standard") or requirement.get("ref") or NO_DATA,
    }


def _by_host(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[str(row.get("host") or NO_DATA)].append(row)
    return dict(sorted(grouped.items()))


def _top_priorities(findings: list[dict[str, Any]], limit: int = 20) -> list[dict[str, Any]]:
    buckets: dict[tuple[str, str], dict[str, Any]] = {}
    for finding in findings:
        if finding.get("type") == "software_vulnerability":
            key = ("cve", str(finding.get("cve") or finding.get("finding_uid")))
            title = str(finding.get("cve") or finding.get("title") or finding.get("finding_uid"))
        else:
            key = ("config", str(finding.get("requirement", {}).get("id") or finding.get("title") or finding.get("finding_uid")))
            title = str(finding.get("title") or finding.get("finding_uid"))
        item = buckets.setdefault(
            key,
            {"title": title, "type": finding.get("type"), "severity": _severity(finding), "assets": set(), "count": 0, "recommendation": finding.get("remediation", {}).get("summary", NO_DATA)},
        )
        item["count"] += 1
        item["assets"].update(finding.get("affected_assets", []) or [])
        if severity_rank(_severity(finding)) > severity_rank(item["severity"]):
            item["severity"] = _severity(finding)
    priorities = []
    for item in buckets.values():
        item["assets"] = sorted(item["assets"])
        priorities.append(item)
    return sorted(priorities, key=lambda item: (-severity_rank(item["severity"]), -int(item["count"]), item["title"]))[:limit]


def _conclusion(stats: dict[str, Any]) -> str:
    hosts = stats["hosts_count"]
    total = stats["included_findings"]
    critical_high = stats["by_severity"].get("critical", 0) + stats["by_severity"].get("high", 0)
    if total == 0:
        return f"Проверено устройств: {hosts}. По заданным критериям значимые нарушения не выявлены."
    risk = "основной риск связан с критичными и высокими находками" if critical_high else "основной риск связан с нарушениями среднего и низкого уровня"
    return (
        f"Проверено устройств: {hosts}. В основной части отчёта отражено {total} значимых находок. "
        f"Выявлено CVE: {stats['unique_cve']}, конфигурационных нарушений: {stats['configuration_failures']}. "
        f"{risk}. В первую очередь рекомендуется устранить записи из раздела приоритетов устранения."
    )


def build_technical_report(raw_findings: list[dict[str, Any]], raw_appendix: list[dict[str, Any]] | None = None, options: ReportOptions | None = None) -> dict[str, Any]:
    options = options or ReportOptions()
    normalized = [item for item in (normalize_finding(raw) for raw in raw_findings) if item is not None]
    deduped = deduplicate_findings(normalized)
    for finding in deduped:
        finding.update(calculate_priority(finding))

    min_severity = "low" if options.include_low else options.min_severity
    min_rank = severity_rank(min_severity)
    candidates = []
    dropped = Counter()
    for finding in deduped:
        status = _status(finding.get("status"))
        severity = _severity(finding)
        if status == "pass" and not options.include_passed:
            dropped["passed"] += 1
            continue
        if severity_rank(severity) < min_rank:
            dropped["severity"] += 1
            continue
        if status not in {"fail", "unknown"} and not options.include_passed:
            dropped["status"] += 1
            continue
        candidates.append(finding)

    included = sorted(candidates, key=lambda item: (-severity_rank(_severity(item)), -int(item.get("priority_score", 0)), item.get("finding_uid", "")))
    limited = included[: max(0, options.max_records)]
    if len(included) > len(limited):
        dropped["limit"] += len(included) - len(limited)
    if options.summary_only:
        limited = limited[:10]

    from reporting.aggregation.asset_inventory import build_asset_inventory

    assets = build_asset_inventory(deduped, None)
    software = [_software_row(item, assets) for item in limited if item.get("type") == "software_vulnerability"]
    config = [_config_row(item, assets) for item in limited if item.get("type") == "configuration_noncompliance"]
    all_statuses = Counter(_status(item.get("status")) for item in deduped)
    included_severities = Counter(_severity(item) for item in limited)
    stats = {
        "processed_findings": len(raw_findings),
        "normalized_findings": len(normalized),
        "unique_findings": len(deduped),
        "included_findings": len(limited),
        "dropped": dict(dropped),
        "hosts_count": len(_host_names(deduped)),
        "hosts": _host_names(deduped),
        "unique_cve": len({item.get("cve") for item in deduped if item.get("cve")}),
        "vulnerable_packages": len({(tuple(item.get("affected_assets", []) or []), item.get("package", {}).get("name")) for item in deduped if item.get("type") == "software_vulnerability"}),
        "configuration_failures": sum(1 for item in deduped if item.get("type") == "configuration_noncompliance" and _status(item.get("status")) == "fail"),
        "by_severity": {severity: included_severities.get(severity, 0) for severity in SEVERITIES},
        "by_status": {status: all_statuses.get(status, 0) for status in STATUSES},
        "software_vulnerabilities": len(software),
        "configuration_findings": len(config),
    }

    report = {
        "title": "Технический отчёт по результатам автоматизированной проверки ИБ",
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "system_name": options.system_name,
        "tool_version": options.tool_version,
        "source": options.source_name,
        "options": options.__dict__,
        "assets": assets,
        "stats": stats,
        "software_by_host": _by_host(software),
        "configuration_by_host": _by_host(config),
        "priorities": _top_priorities(limited),
        "passports": [_finding_passport(item) for item in limited],
        "conclusion": _conclusion(stats),
        "raw_appendix": raw_appendix or [],
    }
    LOG.info("report findings included=%s dropped=%s", len(limited), dict(dropped))
    return report


def _markdown_cell(value: Any) -> str:
    if isinstance(value, list):
        value = ", ".join(str(item) for item in value)
    return str(value if value not in (None, "") else NO_DATA).replace("|", "\\|").replace("\n", "<br>")


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2)


def _env(html: bool = False) -> Environment:
    env = Environment(
        loader=FileSystemLoader(TEMPLATES_DIR),
        autoescape=select_autoescape(["html", "xml"]) if html else False,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["md"] = _markdown_cell
    env.filters["json"] = _json
    return env


def render_technical_report(report: dict[str, Any], output_path: str | pathlib.Path, output_format: str) -> None:
    path = pathlib.Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    template_name = "technical_mvp.html" if output_format == "html" else "technical_mvp.md"
    rendered = _env(html=output_format == "html").get_template(template_name).render(report=report)
    path.write_text(rendered.rstrip() + "\n", encoding="utf-8")
