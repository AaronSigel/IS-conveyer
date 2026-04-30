#!/usr/bin/env python3
import argparse
import json
import pathlib
import re
import sys
from collections import Counter
from datetime import datetime

import yaml
from jinja2 import Environment, FileSystemLoader


PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_FINDINGS = PROJECT_ROOT / "artifacts" / "unified-findings.json"
DEFAULT_OUTPUT = PROJECT_ROOT / "artifacts" / "draft-report.md"
DEFAULT_PROFILE = PROJECT_ROOT / "profiles" / "host-baseline-v1.yml"
DEFAULT_METADATA = PROJECT_ROOT / "config" / "report-metadata.yml"
TEMPLATES_DIR = PROJECT_ROOT / "report" / "templates"
TECHNICAL_TEMPLATE = "technical-report.md.j2"
PASSPORT_TEMPLATE = "vulnerability-passport.md.j2"

UNKNOWN = "не определено"
NOT_APPLICABLE = "не применимо"
NO_DATA = "данные отсутствуют"
SEVERITIES = ("critical", "high", "medium", "low", "info")
STATUS_ALIASES = {"failed": "fail", "failure": "fail", "passed": "pass"}
SOURCE_ALIASES = {
    "wazuh_sca": {"wazuh_sca", "wazuh-api-sca", "wazuh-api", "wazuh sca"},
    "wazuh_vulnerability": {
        "wazuh_vulnerability",
        "wazuh-indexer-vulnerabilities",
        "wazuh-vulnerability",
        "wazuh vulnerability",
    },
}


def parse_args():
    parser = argparse.ArgumentParser(description="Generate a technical host security assessment report.")
    parser.add_argument("--findings", default=None, help="Path to unified findings JSON.")
    parser.add_argument("--input", dest="input_alias", default=None, help="Backward compatible alias for --findings.")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="Path to markdown report.")
    parser.add_argument("--profile", default=str(DEFAULT_PROFILE), help="Path to assessment profile YAML.")
    parser.add_argument("--metadata", default=str(DEFAULT_METADATA), help="Path to report metadata YAML.")
    parser.add_argument("--status", help="Comma-separated status filter.")
    parser.add_argument("--severity", help="Comma-separated severity filter.")
    parser.add_argument("--category", help="Comma-separated category filter.")
    parser.add_argument("--source", help="Comma-separated source filter.")
    parser.add_argument("--host", help="Comma-separated host filter.")
    parser.add_argument("--rule-id", help="Comma-separated rule_id filter.")
    parser.add_argument("--finding-type", help="Comma-separated finding_type filter.")
    parser.add_argument("--cvss-min", type=float, help="Minimum CVSS base score.")
    parser.add_argument("--cvss-max", type=float, help="Maximum CVSS base score.")
    args = parser.parse_args()
    args.findings = args.findings or args.input_alias or str(DEFAULT_FINDINGS)
    return args


def load_findings(path):
    path = pathlib.Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Findings file not found: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("Findings file must contain a JSON array")
    return data


def load_yaml_file(path):
    if not path:
        return {}
    path = pathlib.Path(path)
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def load_profile(path):
    return load_yaml_file(path)


def load_metadata(path):
    metadata = load_yaml_file(path)
    metadata.setdefault("report", {})
    metadata.setdefault("assessment", {})
    metadata.setdefault("stand", {})
    metadata.setdefault("tools", [])
    return metadata


def split_values(raw):
    if raw is None:
        return None
    values = [value.strip() for value in raw.split(",") if value.strip()]
    return values or None


def normalize_status(value):
    lowered = str(value or "").strip().lower()
    return STATUS_ALIASES.get(lowered, lowered)


def source_tokens(value):
    lowered = str(value or "").strip().lower()
    tokens = {lowered}
    for canonical, aliases in SOURCE_ALIASES.items():
        if lowered == canonical or lowered in aliases:
            tokens.update(aliases)
            tokens.add(canonical)
    return tokens


def build_filters(args):
    filters = {
        "status": split_values(args.status),
        "severity": split_values(args.severity),
        "category": split_values(args.category),
        "source": split_values(args.source),
        "host": split_values(args.host),
        "rule_id": split_values(args.rule_id),
        "finding_type": split_values(args.finding_type),
        "cvss_min": args.cvss_min,
        "cvss_max": args.cvss_max,
    }
    return {key: value for key, value in filters.items() if value is not None}


def filter_rows(filters):
    labels = {
        "status": "status",
        "severity": "severity",
        "category": "category",
        "source": "source",
        "host": "host",
        "rule_id": "rule_id",
        "finding_type": "finding_type",
        "cvss_min": "cvss_base_score",
        "cvss_max": "cvss_base_score",
    }
    ops = {
        "cvss_min": "больше или равно",
        "cvss_max": "меньше или равно",
    }
    rows = []
    for key, value in filters.items():
        condition = ops.get(key, "входит в")
        if isinstance(value, list):
            rendered = ", ".join(str(item) for item in value)
        else:
            rendered = str(value)
        rows.append({"field": labels[key], "condition": condition, "value": rendered})
    return rows


def list_match(actual, expected_values, *, normalizer=None, source=False):
    if actual is None:
        return False
    actual_text = str(actual)
    if source:
        actual_set = source_tokens(actual_text)
        return any(source_tokens(value) & actual_set for value in expected_values)
    if normalizer:
        actual_text = normalizer(actual_text)
        expected = {normalizer(value) for value in expected_values}
    else:
        actual_text = actual_text.strip().lower()
        expected = {str(value).strip().lower() for value in expected_values}
    return actual_text in expected


def get_cvss_score(finding):
    cvss = finding.get("cvss")
    if isinstance(cvss, dict) and cvss.get("base_score") is not None:
        return float(cvss["base_score"])
    for item in finding.get("evidence") or []:
        match = re.search(r"CVSS\s+base:\s*([0-9]+(?:\.[0-9]+)?)", str(item), re.IGNORECASE)
        if match:
            return float(match.group(1))
    return None


def infer_finding_type(finding):
    explicit = finding.get("finding_type")
    if explicit:
        return explicit
    source = str(finding.get("source", "")).lower()
    category = str(finding.get("category", "")).lower()
    if "vulnerab" in source or category == "vulnerability":
        return "software_vulnerability"
    if category == "software":
        return "insecure_package"
    return "configuration_noncompliance"


def apply_filters(findings, filters):
    selected = []
    for finding in findings:
        if filters.get("status") and not list_match(finding.get("status"), filters["status"], normalizer=normalize_status):
            continue
        if filters.get("severity") and not list_match(finding.get("severity"), filters["severity"]):
            continue
        if filters.get("category") and not list_match(finding.get("category"), filters["category"]):
            continue
        if filters.get("source") and not list_match(finding.get("source"), filters["source"], source=True):
            continue
        if filters.get("host") and not list_match(finding.get("host"), filters["host"]):
            continue
        if filters.get("rule_id") and not list_match(finding.get("rule_id"), filters["rule_id"]):
            continue
        if filters.get("finding_type") and not list_match(infer_finding_type(finding), filters["finding_type"]):
            continue
        if "cvss_min" in filters or "cvss_max" in filters:
            score = get_cvss_score(finding)
            if score is None:
                continue
            if "cvss_min" in filters and score < filters["cvss_min"]:
                continue
            if "cvss_max" in filters and score > filters["cvss_max"]:
                continue
        selected.append(finding)
    return selected


def build_summary(selected_findings):
    by_severity = Counter(str(item.get("severity", "info")).lower() for item in selected_findings)
    by_category = Counter(str(item.get("category", UNKNOWN)).lower() for item in selected_findings)
    by_finding_type = Counter(infer_finding_type(item) for item in selected_findings)
    hosts = {str(item.get("host")) for item in selected_findings if item.get("host")}
    return {
        "hosts_count": len(hosts),
        "selected_findings_count": len(selected_findings),
        "by_severity": {severity: by_severity.get(severity, 0) for severity in SEVERITIES},
        "by_category": dict(sorted(by_category.items())),
        "by_finding_type": dict(sorted(by_finding_type.items())),
        "software_vulnerabilities": by_finding_type.get("software_vulnerability", 0),
        "configuration_findings": sum(
            count for key, count in by_finding_type.items() if key != "software_vulnerability"
        ),
    }


def build_profile_index(profile):
    index = {}
    for section in ("checks", "vulnerabilities", "rules"):
        for item in profile.get(section, []) or []:
            keys = [item.get("id"), item.get("rule_id"), item.get("cve")]
            if item.get("sca_check_id") is not None:
                keys.append(str(item["sca_check_id"]))
            for key in keys:
                if key:
                    index[str(key).lower()] = item
    return index


def profile_meta_for(finding, profile_index):
    keys = [
        finding.get("rule_id"),
        finding.get("vulnerability_id"),
        finding.get("cve"),
        finding.get("sca_check_id"),
    ]
    external_ids = finding.get("external_ids") or {}
    if isinstance(external_ids, dict):
        keys.extend(external_ids.values())
    for key in keys:
        if key is None:
            continue
        item = profile_index.get(str(key).lower())
        if item:
            return item
    return {}


def host_metadata(metadata, host):
    for item in metadata.get("stand", {}).get("hosts", []) or []:
        if str(item.get("name", "")).lower() == str(host or "").lower():
            return item
    return {}


def first_value(*values, default=UNKNOWN):
    for value in values:
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        return value
    return default


def nested(data, *keys):
    current = data
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def evidence_text(finding):
    evidence = finding.get("evidence")
    if isinstance(evidence, list):
        return "<br>".join(str(item) for item in evidence) if evidence else NO_DATA
    return first_value(evidence, default=NO_DATA)


def package_from_evidence(finding):
    for item in finding.get("evidence") or []:
        match = re.search(r"Package:\s*(.+)", str(item), re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return None


def cve_from_finding(finding):
    external_ids = finding.get("external_ids") or {}
    if isinstance(external_ids, dict) and external_ids.get("cve"):
        return external_ids["cve"]
    if finding.get("cve"):
        return finding["cve"]
    for item in finding.get("evidence") or []:
        match = re.search(r"\b(CVE-\d{4}-\d{4,})\b", str(item), re.IGNORECASE)
        if match:
            return match.group(1).upper()
    match = re.search(r"\b(CVE-\d{4}-\d{4,})\b", str(finding.get("rule_id", "")), re.IGNORECASE)
    return match.group(1).upper() if match else None


def external_ids_text(finding, passport_meta):
    parts = []
    if finding.get("rule_id"):
        parts.append(f"Rule ID: {finding['rule_id']}")
    cve = cve_from_finding(finding)
    if cve:
        parts.append(f"CVE: {cve}")
    cwe = first_value(
        nested(finding, "external_ids", "cwe"),
        nested(passport_meta, "external_ids", "cwe"),
        default=None,
    )
    if cwe:
        parts.append(f"CWE: {cwe}")
    bdu = first_value(nested(finding, "external_ids", "bdu"), default=None)
    if bdu:
        parts.append(f"BDU: {bdu}")
    return "; ".join(parts) if parts else NO_DATA


def cvss_text(finding, software_vulnerability):
    if not software_vulnerability:
        return NOT_APPLICABLE
    score = get_cvss_score(finding)
    vector = nested(finding, "cvss", "vector")
    if score is None:
        return NO_DATA
    return f"{score:g}" + (f" ({vector})" if vector else "")


def affected_component_text(finding, passport_meta):
    component = first_value(finding.get("affected_component"), passport_meta.get("affected_component"), default={})
    if not isinstance(component, dict):
        return str(component)
    package = component.get("package") or component.get("name")
    version = component.get("version")
    if package and version:
        return f"{package} {version}"
    if package:
        return str(package)
    return package_from_evidence(finding) or NOT_APPLICABLE


def service_port_protocol_text(finding, passport_meta):
    component = first_value(finding.get("affected_component"), passport_meta.get("affected_component"), default={})
    if not isinstance(component, dict):
        return NOT_APPLICABLE
    service = component.get("service") or component.get("name")
    port = component.get("port")
    protocol = component.get("protocol")
    parts = [str(value) for value in (service, port, protocol) if value not in (None, "")]
    return " / ".join(parts) if parts else NOT_APPLICABLE


def detection_method(finding, passport_meta, software_vulnerability):
    if finding.get("detection_method"):
        return finding["detection_method"]
    if passport_meta.get("detection_method"):
        return passport_meta["detection_method"]
    if software_vulnerability:
        return "Wazuh Vulnerability Detector"
    sca_id = first_value(finding.get("sca_check_id"), passport_meta.get("sca_check_id"), default=None)
    if sca_id:
        return f"Wazuh SCA check {sca_id}"
    return "Wazuh SCA"


def build_passports(selected_findings, profile_index, metadata, report_datetime):
    passports = []
    for index, finding in enumerate(selected_findings, start=1):
        passports.append(build_passport(finding, index, profile_index, metadata, report_datetime))
    return passports


def build_passport(finding, index, profile_index, metadata, report_datetime):
    profile_rule = profile_meta_for(finding, profile_index)
    passport_meta = profile_rule.get("passport", {}) if isinstance(profile_rule.get("passport"), dict) else {}
    finding_type = first_value(finding.get("finding_type"), passport_meta.get("finding_type"), infer_finding_type(finding))
    software_vulnerability = finding_type == "software_vulnerability" or infer_finding_type(finding) == "software_vulnerability"
    host_meta = host_metadata(metadata, finding.get("host"))
    year = report_datetime.year
    passport_id = first_value(finding.get("vulnerability_id"), default=f"ISCV-{year}-{index:04d}")
    if software_vulnerability:
        vulnerability_class = "Уязвимость программного обеспечения"
    else:
        vulnerability_class = first_value(
            finding.get("vulnerability_class"),
            passport_meta.get("vulnerability_class"),
            default="Уязвимость конфигурации / несоответствие",
        )

    return {
        "passport_id": passport_id,
        "title": first_value(finding.get("title"), profile_rule.get("title")),
        "external_ids_text": external_ids_text(finding, passport_meta),
        "vulnerability_class": vulnerability_class,
        "affected_software": affected_component_text(finding, passport_meta),
        "weakness_id": first_value(
            finding.get("weakness_id"),
            passport_meta.get("weakness_id"),
            nested(finding, "external_ids", "cwe"),
            nested(passport_meta, "external_ids", "cwe"),
            default=UNKNOWN,
        ),
        "weakness_type": first_value(finding.get("weakness_type"), passport_meta.get("weakness_type")),
        "location": first_value(finding.get("location"), passport_meta.get("location")),
        "host": first_value(finding.get("host"), default=UNKNOWN),
        "os_platform": first_value(finding.get("os_platform"), host_meta.get("os"), default=UNKNOWN),
        "service_port_protocol": service_port_protocol_text(finding, passport_meta),
        "detection_method": detection_method(finding, passport_meta, software_vulnerability),
        "source": first_value(finding.get("source"), default=UNKNOWN),
        "severity": first_value(finding.get("severity"), default=UNKNOWN),
        "cvss_text": cvss_text(finding, software_vulnerability),
        "status": first_value(finding.get("status"), default=UNKNOWN),
        "detected_at": first_value(finding.get("detected_at"), default=NO_DATA),
        "description": first_value(finding.get("description"), profile_rule.get("rationale"), finding.get("title"), default=NO_DATA),
        "evidence": evidence_text(finding),
        "impact": first_value(finding.get("impact"), passport_meta.get("impact"), default=NO_DATA),
        "remediation": first_value(finding.get("remediation"), profile_rule.get("remediation"), default=NO_DATA),
    }


def jinja_env():
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        trim_blocks=True,
        lstrip_blocks=True,
        autoescape=False,
    )
    env.filters["md"] = markdown_cell
    return env


def markdown_cell(value):
    text = str(value if value is not None else "")
    return text.replace("|", "\\|").replace("\n", "<br>")


def render_passport(passport, section_number):
    return jinja_env().get_template(PASSPORT_TEMPLATE).render(passport=passport, section_number=section_number).strip()


def conclusion(summary):
    if summary["selected_findings_count"] == 0:
        return "По заданным критериям фильтрации уязвимости и несоответствия не выявлены."
    if summary["by_severity"].get("critical", 0) or summary["by_severity"].get("high", 0):
        return (
            "По результатам проверки выявлены уязвимости и несоответствия, требующие приоритетного устранения. "
            "Наиболее значимыми являются результаты с уровнем опасности `critical` и `high`."
        )
    return (
        "По результатам проверки выявлены уязвимости и несоответствия умеренного и низкого уровня опасности. "
        "Рекомендуется выполнить корректирующие мероприятия согласно паспортам."
    )


def assessment_text(summary):
    if summary["selected_findings_count"] == 0:
        return "По заданным критериям фильтрации уязвимости и несоответствия не выявлены."
    return (
        "По результатам проверки выявлены уязвимости и несоответствия, требующие устранения. "
        "Наиболее приоритетными являются результаты с уровнем опасности `critical` и `high`."
    )


def profile_name(profile, profile_path):
    return profile.get("profile") or pathlib.Path(profile_path).stem or UNKNOWN


def build_context(args, findings, selected_findings, filters, metadata, profile, passports, report_datetime):
    report_meta = metadata.get("report", {})
    assessment = metadata.get("assessment", {})
    hosts = metadata.get("stand", {}).get("hosts", []) or []
    checked_hosts = [host for host in hosts if "проверяем" in str(host.get("role", "")).lower()]
    summary = build_summary(selected_findings)
    return {
        "report_title": str(report_meta.get("title") or "Отчёт о результатах проверки защищённости хостов").upper(),
        "report": {
            "id": report_meta.get("id") or f"IS-CONVEYER-REPORT-{report_datetime.year}-001",
            "generated_at": report_datetime.isoformat(timespec="seconds"),
            "object_name": report_meta.get("object_name") or "Тестовый стенд информационной системы",
            "profile": profile_name(profile, args.profile),
            "sources": report_meta.get("sources") or "Wazuh SCA / Syscollector / Vulnerability Detector",
            "format": "Паспорт выявленной уязвимости / несоответствия",
            "passport_basis": report_meta.get("passport_basis") or "ГОСТ Р 56545-2015",
            "passports_count": len(passports),
        },
        "purpose": report_meta.get("purpose") or "Проверка соответствия конфигурации хостов базовому профилю информационной безопасности",
        "scope": report_meta.get("scope") or "Системное ПО проверяемых хостов",
        "limitations": assessment.get("limitations") or ["Ограничения проверки не заданы."],
        "filters": filters,
        "filter_rows": filter_rows(filters),
        "hosts": checked_hosts or hosts,
        "stand_hosts": hosts,
        "tools": metadata.get("tools", []) or [],
        "summary": summary,
        "assessment_text": assessment_text(summary),
        "conclusion": conclusion(summary),
        "passports": passports,
        "all_findings_count": len(findings),
    }


def render_report(context, output_path):
    rendered_passports = []
    for index, passport in enumerate(context["passports"], start=1):
        rendered_passports.append(render_passport(passport, f"5.{index}"))
    context = dict(context)
    context["rendered_passports"] = rendered_passports
    report = jinja_env().get_template(TECHNICAL_TEMPLATE).render(**context)
    output_path = pathlib.Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report.rstrip() + "\n", encoding="utf-8")


def main():
    args = parse_args()
    findings = load_findings(args.findings)
    profile = load_profile(args.profile)
    metadata = load_metadata(args.metadata)
    filters = build_filters(args)
    selected_findings = apply_filters(findings, filters)
    profile_index = build_profile_index(profile)
    report_datetime = datetime.now().astimezone()
    passports = build_passports(selected_findings, profile_index, metadata, report_datetime)
    context = build_context(args, findings, selected_findings, filters, metadata, profile, passports, report_datetime)
    render_report(context, args.output)
    print(f"Technical report written to {args.output}")
    print(f"Selected findings: {len(selected_findings)} of {len(findings)}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"generate-report.py failed: {exc}", file=sys.stderr)
        sys.exit(1)
