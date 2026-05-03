from __future__ import annotations

import json
import pathlib
import re
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from reporting import build_normalized_report
from reporting.renderers import render_html as render_technical_html
from reporting.renderers import render_json as render_technical_json
from reporting.renderers import render_pdf as render_technical_pdf

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_PROFILE = PROJECT_ROOT / "profiles" / "cis_ubuntu24-04.yml"
DEFAULT_ENRICHMENT = PROJECT_ROOT / "config" / "finding-enrichment.yml"

UNKNOWN = "не определено"
NOT_APPLICABLE = "не применимо"
NO_DATA = "данные отсутствуют"
STATUS_ALIASES = {"failed": "fail", "failure": "fail", "passed": "pass"}


def load_yaml_file(path: str | Path | None) -> dict[str, Any]:
    if not path:
        return {}
    path = pathlib.Path(path)
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def load_profile(path: str | Path = DEFAULT_PROFILE) -> dict[str, Any]:
    return load_yaml_file(path)


def load_enrichment(path: str | Path = DEFAULT_ENRICHMENT) -> dict[str, Any]:
    path = pathlib.Path(path)
    if not path.exists():
        return {}
    if path.suffix.lower() == ".json":
        return json.loads(path.read_text(encoding="utf-8"))
    return load_yaml_file(path)


def normalize_status(value: Any) -> str:
    lowered = str(value or "").strip().lower()
    return STATUS_ALIASES.get(lowered, lowered)


def get_cvss_score(finding: dict[str, Any]) -> float | None:
    cvss = finding.get("cvss")
    if isinstance(cvss, dict) and cvss.get("base_score") is not None:
        return float(cvss["base_score"])
    for item in finding.get("evidence") or []:
        match = re.search(r"CVSS\s+base:\s*([0-9]+(?:\.[0-9]+)?)", str(item), re.IGNORECASE)
        if match:
            return float(match.group(1))
    return None


def severity_from_cvss(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def infer_finding_type(finding: dict[str, Any]) -> str:
    explicit = finding.get("finding_type")
    if explicit:
        return str(explicit)
    source = str(finding.get("source", "")).lower()
    category = str(finding.get("category", "")).lower()
    if "vulnerab" in source or category == "vulnerability":
        return "software_vulnerability"
    if category == "software":
        return "insecure_package"
    return "configuration_noncompliance"


def normalized_severity(finding: dict[str, Any]) -> str:
    if infer_finding_type(finding) == "software_vulnerability":
        score = get_cvss_score(finding)
        severity = severity_from_cvss(score)
        if severity:
            return severity
    return str(finding.get("severity", "info")).lower()


def build_profile_index(profile: dict[str, Any], enrichment: dict[str, Any] | None = None) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    sources: list[dict[str, Any]] = [profile]
    if enrichment:
        sources.append({"checks": enrichment.get("sca_rules", []), "vulnerabilities": enrichment.get("cves", [])})
    for source in sources:
        for section in ("checks", "vulnerabilities", "rules"):
            for item in source.get(section, []) or []:
                keys = [item.get("id"), item.get("rule_id"), item.get("cve")]
                if item.get("sca_check_id") is not None:
                    keys.append(str(item["sca_check_id"]))
                for key in keys:
                    if not key:
                        continue
                    normalized = str(key).lower()
                    if normalized in index:
                        merged = dict(index[normalized])
                        merged.update(item)
                        index[normalized] = merged
                    else:
                        index[normalized] = item
    return index


def profile_meta_for(finding: dict[str, Any], profile_index: dict[str, dict[str, Any]]) -> dict[str, Any]:
    keys = [finding.get("rule_id"), finding.get("vulnerability_id"), finding.get("cve"), finding.get("sca_check_id")]
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


def host_metadata(metadata: dict[str, Any], host: Any) -> dict[str, Any]:
    for item in metadata.get("stand", {}).get("hosts", []) or []:
        if str(item.get("name", "")).lower() == str(host or "").lower():
            return item
    return {}


def first_value(*values: Any, default: Any = UNKNOWN) -> Any:
    for value in values:
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        return value
    return default


def nested(data: Any, *keys: str) -> Any:
    current = data
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def wazuh_sca_data(finding: dict[str, Any]) -> dict[str, Any]:
    data = finding.get("wazuh_sca")
    return data if isinstance(data, dict) else {}


def wazuh_vulnerability_data(finding: dict[str, Any]) -> dict[str, Any]:
    data = finding.get("wazuh_vulnerability")
    return data if isinstance(data, dict) else {}


def multiline_text(value: Any) -> str:
    if isinstance(value, list):
        values = [str(item) for item in value if item not in (None, "")]
        return "\n".join(values) if values else NO_DATA
    return str(first_value(value, default=NO_DATA))


def evidence_text(finding: dict[str, Any]) -> str:
    evidence = finding.get("evidence")
    if isinstance(evidence, list):
        return "<br>".join(str(item) for item in evidence) if evidence else NO_DATA
    return str(first_value(evidence, default=NO_DATA))


def package_from_evidence(finding: dict[str, Any]) -> str | None:
    for item in finding.get("evidence") or []:
        match = re.search(r"Package:\s*(.+)", str(item), re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return None


def cve_from_finding(finding: dict[str, Any]) -> str | None:
    external_ids = finding.get("external_ids") or {}
    if isinstance(external_ids, dict) and external_ids.get("cve"):
        return str(external_ids["cve"])
    if finding.get("cve"):
        return str(finding["cve"])
    for item in finding.get("evidence") or []:
        match = re.search(r"\b(CVE-\d{4}-\d{4,})\b", str(item), re.IGNORECASE)
        if match:
            return match.group(1).upper()
    match = re.search(r"\b(CVE-\d{4}-\d{4,})\b", str(finding.get("rule_id", "")), re.IGNORECASE)
    return match.group(1).upper() if match else None


def external_ids_text(finding: dict[str, Any], passport_meta: dict[str, Any]) -> str:
    parts: list[str] = []
    if finding.get("rule_id"):
        parts.append(f"Rule ID: {finding['rule_id']}")
    cve = cve_from_finding(finding)
    if cve:
        parts.append(f"CVE: {cve}")
    cwe = first_value(nested(finding, "external_ids", "cwe"), nested(passport_meta, "external_ids", "cwe"), default=None)
    if cwe:
        parts.append(f"CWE: {cwe}")
    bdu = first_value(nested(finding, "external_ids", "bdu"), default=None)
    if bdu:
        parts.append(f"BDU: {bdu}")
    return "; ".join(parts) if parts else NO_DATA


def cvss_text(finding: dict[str, Any], software_vulnerability: bool) -> str:
    if not software_vulnerability:
        return NOT_APPLICABLE
    score = get_cvss_score(finding)
    vector = nested(finding, "cvss", "vector")
    if score is None:
        return NO_DATA
    return f"{score:g}" + (f" ({vector})" if vector else "")


def affected_component_text(finding: dict[str, Any], passport_meta: dict[str, Any]) -> str:
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


def package_name(finding: dict[str, Any], passport_meta: dict[str, Any]) -> str:
    component = first_value(finding.get("affected_component"), passport_meta.get("affected_component"), default={})
    if isinstance(component, dict):
        return str(first_value(component.get("package"), component.get("name"), default=package_from_evidence(finding) or NOT_APPLICABLE))
    return package_from_evidence(finding) or NOT_APPLICABLE


def installed_version(finding: dict[str, Any], passport_meta: dict[str, Any]) -> str:
    component = first_value(finding.get("affected_component"), passport_meta.get("affected_component"), default={})
    if isinstance(component, dict):
        return str(first_value(component.get("version"), default=NOT_APPLICABLE))
    package = package_from_evidence(finding)
    if package:
        parts = package.rsplit(" ", 1)
        if len(parts) == 2:
            return parts[1]
    return NOT_APPLICABLE


def service_port_protocol_text(finding: dict[str, Any], passport_meta: dict[str, Any]) -> str:
    component = first_value(finding.get("affected_component"), passport_meta.get("affected_component"), default={})
    if not isinstance(component, dict):
        return NOT_APPLICABLE
    service = component.get("service") or component.get("name")
    port = component.get("port")
    protocol = component.get("protocol")
    parts = [str(value) for value in (service, port, protocol) if value not in (None, "")]
    return " / ".join(parts) if parts else NOT_APPLICABLE


def detection_method(finding: dict[str, Any], passport_meta: dict[str, Any], software_vulnerability: bool) -> str:
    if finding.get("detection_method"):
        return str(finding["detection_method"])
    if passport_meta.get("detection_method"):
        return str(passport_meta["detection_method"])
    if software_vulnerability:
        return "Wazuh Vulnerability Detector"
    sca_id = first_value(finding.get("sca_check_id"), passport_meta.get("sca_check_id"), default=None)
    if sca_id:
        return f"Wazuh SCA check {sca_id}"
    return "Wazuh SCA"


def references_text(references: list[Any]) -> str:
    if not references:
        return NO_DATA
    return "\n".join(str(item) for item in references if item not in (None, "")) or NO_DATA


def compliance_passport_rows(compliance_text: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    if not compliance_text or compliance_text == NO_DATA:
        return rows
    for item in str(compliance_text).splitlines():
        if ":" in item:
            key, value = item.split(":", 1)
            rows.append({"label": key.strip(), "value": value.strip() or NO_DATA})
        elif item.strip():
            rows.append({"label": "Compliance", "value": item.strip()})
    return rows


def wazuh_sca_passport_rows(passport: dict[str, Any]) -> list[dict[str, Any]]:
    rows = [
        {"label": "ID", "value": passport["wazuh_id"]},
        {"label": "Title", "value": passport["wazuh_title"]},
        {"label": "Target", "value": passport["wazuh_target"]},
        {"label": "Result", "value": passport["wazuh_result"]},
        {"label": "Rationale", "value": passport["wazuh_rationale"]},
        {"label": "Remediation", "value": passport["wazuh_remediation"]},
        {"label": "Description", "value": passport["wazuh_description"]},
        {"label": "Checks", "value": passport["wazuh_checks"]},
    ]
    rows.extend(compliance_passport_rows(passport["wazuh_compliance"]))
    return rows


def generic_passport_rows(passport: dict[str, Any]) -> list[dict[str, Any]]:
    discovery = "\n".join(str(item) for item in [passport["detection_method"]] if item and item != NO_DATA)
    other_info_parts = [
        f"Хост: {passport['host']}",
        f"Статус: {passport['status_ru']}",
        f"Источник: {passport['source_ru']}",
        f"Категория: {passport['category_ru']}",
    ]
    if passport.get("references"):
        other_info_parts.append(f"Ссылки:\n{references_text(passport['references'])}")
    return [
        {"label": "Наименование уязвимости", "value": passport["title_ru"]},
        {"label": "Идентификатор уязвимости", "value": passport["passport_id"]},
        {"label": "Идентификаторы других систем описаний уязвимостей", "value": passport["external_ids_text"]},
        {"label": "Краткое описание уязвимости", "value": passport["description_ru"]},
        {"label": "Класс уязвимости", "value": passport["vulnerability_class"]},
        {"label": "Наименование ПО и его версия", "value": passport["affected_software"]},
        {"label": "Служба (порт), которая используется для функционирования ПО", "value": passport["service_port_protocol"]},
        {"label": "Язык программирования ПО", "value": NOT_APPLICABLE},
        {"label": "Тип недостатка", "value": passport["weakness_type"]},
        {"label": "Место возникновения (проявления) уязвимости", "value": passport["location"]},
        {"label": "Идентификатор типа недостатка", "value": passport["weakness_id"]},
        {"label": "Наименование операционной системы и тип аппаратной платформы", "value": passport["os_platform"]},
        {"label": "Дата выявления уязвимости", "value": passport["detected_at"]},
        {"label": "Автор, опубликовавший информацию о выявленной уязвимости", "value": passport["source_ru"]},
        {"label": "Способ (правило) обнаружения уязвимости", "value": discovery or NO_DATA},
        {"label": "Критерии опасности уязвимости", "value": passport["cvss_text"]},
        {"label": "Степень опасности уязвимости", "value": passport["severity_normalized"]},
        {"label": "Возможные меры по устранению уязвимости", "value": passport["remediation_ru"]},
        {"label": "Прочая информация", "value": "\n".join(other_info_parts)},
    ]


def package_vulnerability_passport_rows(passport: dict[str, Any]) -> list[dict[str, Any]]:
    rows = generic_passport_rows(passport)
    rows.extend([
        {"label": "agent.id", "value": passport["wazuh_agent_id"]},
        {"label": "agent.name", "value": passport["wazuh_agent_name"]},
        {"label": "agent.type", "value": passport["wazuh_agent_type"]},
        {"label": "agent.version", "value": passport["wazuh_agent_version"]},
        {"label": "host.os.full", "value": passport["wazuh_host_os_full"]},
        {"label": "host.os.kernel", "value": passport["wazuh_host_os_kernel"]},
        {"label": "host.os.name", "value": passport["wazuh_host_os_name"]},
        {"label": "host.os.platform", "value": passport["wazuh_host_os_platform"]},
        {"label": "host.os.type", "value": passport["wazuh_host_os_type"]},
        {"label": "host.os.version", "value": passport["wazuh_host_os_version"]},
        {"label": "package.architecture", "value": passport["wazuh_package_architecture"]},
        {"label": "package.description", "value": passport["wazuh_package_description"]},
        {"label": "package.name", "value": passport["wazuh_package_name"]},
        {"label": "package.size", "value": passport["wazuh_package_size"]},
        {"label": "package.type", "value": passport["wazuh_package_type"]},
        {"label": "package.version", "value": passport["wazuh_package_version"]},
        {"label": "vulnerability.category", "value": passport["wazuh_vulnerability_category"]},
        {"label": "vulnerability.classification", "value": passport["wazuh_vulnerability_classification"]},
        {"label": "vulnerability.description", "value": passport["wazuh_vulnerability_description"]},
        {"label": "vulnerability.detected_at", "value": passport["wazuh_vulnerability_detected_at"]},
        {"label": "vulnerability.enumeration", "value": passport["wazuh_vulnerability_enumeration"]},
        {"label": "vulnerability.id", "value": passport["wazuh_vulnerability_id"]},
        {"label": "vulnerability.published_at", "value": passport["wazuh_vulnerability_published_at"]},
        {"label": "vulnerability.reference", "value": passport["wazuh_vulnerability_reference"]},
        {"label": "vulnerability.scanner.condition", "value": passport["wazuh_scanner_condition"]},
        {"label": "vulnerability.scanner.reference", "value": passport["wazuh_scanner_reference"]},
        {"label": "vulnerability.scanner.source", "value": passport["wazuh_scanner_source"]},
        {"label": "vulnerability.scanner.vendor", "value": passport["wazuh_scanner_vendor"]},
        {"label": "vulnerability.score.base", "value": passport["wazuh_score_base"]},
        {"label": "vulnerability.score.version", "value": passport["wazuh_score_version"]},
        {"label": "vulnerability.severity", "value": passport["wazuh_vulnerability_severity"]},
        {"label": "vulnerability.under_evaluation", "value": passport["wazuh_vulnerability_under_evaluation"]},
        {"label": "_index", "value": passport["wazuh_index"]},
        {"label": "_id", "value": passport["wazuh_document_id"]},
    ])
    return rows


def passport_rows(passport: dict[str, Any]) -> list[dict[str, Any]]:
    if passport.get("show_wazuh_sca"):
        return wazuh_sca_passport_rows(passport)
    if passport.get("template_kind") == "package_vulnerability":
        return package_vulnerability_passport_rows(passport)
    return generic_passport_rows(passport)


def build_passport(
    finding: dict[str, Any],
    index: int,
    profile_index: dict[str, dict[str, Any]],
    metadata: dict[str, Any],
    report_datetime: datetime,
) -> dict[str, Any]:
    profile_rule = profile_meta_for(finding, profile_index)
    passport_meta = profile_rule.get("passport", {}) if isinstance(profile_rule.get("passport"), dict) else {}
    finding_type = first_value(finding.get("finding_type"), passport_meta.get("finding_type"), infer_finding_type(finding))
    software_vulnerability = finding_type == "software_vulnerability" or infer_finding_type(finding) == "software_vulnerability"
    wazuh_sca = wazuh_sca_data(finding)
    wazuh_vulnerability = wazuh_vulnerability_data(finding)
    wazuh_agent = nested(wazuh_vulnerability, "agent") or {}
    wazuh_host_os = nested(wazuh_vulnerability, "host", "os") or {}
    wazuh_vuln = nested(wazuh_vulnerability, "vulnerability") or {}
    wazuh_scanner = nested(wazuh_vulnerability, "vulnerability", "scanner") or {}
    wazuh_score = nested(wazuh_vulnerability, "vulnerability", "score") or {}
    show_wazuh_sca = bool(wazuh_sca) and not software_vulnerability
    host_meta = host_metadata(metadata, finding.get("host"))
    year = report_datetime.year
    passport_id = first_value(finding.get("vulnerability_id"), default=f"ISCV-{year}-{index:04d}")
    vulnerability_class = "Уязвимость программного обеспечения" if software_vulnerability else first_value(
        finding.get("vulnerability_class"),
        passport_meta.get("vulnerability_class"),
        default="Уязвимость конфигурации / несоответствие",
    )
    cvss_score = get_cvss_score(finding)
    cve = cve_from_finding(finding)
    references = first_value(finding.get("references"), wazuh_vuln.get("reference"), passport_meta.get("references"), profile_rule.get("references"), default=[])
    if isinstance(references, str):
        references = [part.strip() for part in references.split(",") if part.strip()]
    if not isinstance(references, list):
        references = []
    category = first_value(finding.get("category"), profile_rule.get("category"), default=UNKNOWN)
    status = normalize_status(first_value(finding.get("status"), default=UNKNOWN))
    severity = normalized_severity(finding)
    source = first_value(finding.get("source"), default=UNKNOWN)
    passport = {
        "passport_id": passport_id,
        "title_ru": first_value(finding.get("title"), profile_rule.get("title")),
        "finding_type_ru": "Уязвимость пакета" if software_vulnerability else "Несоответствие конфигурации",
        "status_ru": status,
        "host": first_value(finding.get("host"), default=UNKNOWN),
        "asset_component": affected_component_text(finding, passport_meta),
        "package_name": package_name(finding, passport_meta) if software_vulnerability else NOT_APPLICABLE,
        "installed_version": installed_version(finding, passport_meta) if software_vulnerability else NOT_APPLICABLE,
        "cve": cve or NOT_APPLICABLE,
        "cvss": cvss_text(finding, software_vulnerability),
        "severity_normalized": severity,
        "category_ru": category,
        "source_ru": source,
        "detected_at": first_value(finding.get("detected_at"), default=NO_DATA),
        "rule_id": first_value(finding.get("rule_id"), default=UNKNOWN),
        "description_ru": first_value(wazuh_sca.get("description") if not software_vulnerability else None, finding.get("description_ru"), finding.get("description"), profile_rule.get("description_ru"), profile_rule.get("rationale"), finding.get("title"), default=NO_DATA),
        "evidence_structured": evidence_text(finding).replace("<br>", "\n"),
        "impact_ru": first_value(wazuh_sca.get("rationale") if not software_vulnerability else None, finding.get("impact_ru"), finding.get("impact"), passport_meta.get("impact"), profile_rule.get("impact_ru"), default=NO_DATA),
        "remediation_ru": first_value(wazuh_sca.get("remediation") if not software_vulnerability else None, finding.get("remediation_ru"), finding.get("remediation"), profile_rule.get("remediation_ru"), profile_rule.get("remediation"), default=NO_DATA),
        "verification_command": first_value(wazuh_sca.get("target") if not software_vulnerability else None, finding.get("verification_command"), profile_rule.get("verification_command"), default=NO_DATA),
        "expected_result": first_value(finding.get("expected_result"), profile_rule.get("expected_result"), default=NO_DATA),
        "references": references,
        "template_kind": "package_vulnerability" if software_vulnerability else "configuration",
        "cvss_base_score": cvss_score,
        "show_wazuh_sca": show_wazuh_sca,
        "wazuh_id": first_value(wazuh_sca.get("id"), finding.get("sca_check_id"), default=NO_DATA),
        "wazuh_title": first_value(wazuh_sca.get("title"), finding.get("title"), default=NO_DATA),
        "wazuh_target": first_value(wazuh_sca.get("target"), default=NO_DATA),
        "wazuh_result": first_value(wazuh_sca.get("result"), finding.get("status"), default=NO_DATA),
        "wazuh_rationale": first_value(wazuh_sca.get("rationale"), finding.get("impact"), default=NO_DATA),
        "wazuh_description": first_value(wazuh_sca.get("description"), finding.get("description"), default=NO_DATA),
        "wazuh_remediation": first_value(wazuh_sca.get("remediation"), finding.get("remediation"), default=NO_DATA),
        "wazuh_checks": multiline_text(wazuh_sca.get("checks")),
        "wazuh_compliance": multiline_text(wazuh_sca.get("compliance")),
        "external_ids_text": external_ids_text(finding, passport_meta),
        "vulnerability_class": vulnerability_class,
        "affected_software": affected_component_text(finding, passport_meta),
        "weakness_id": first_value(finding.get("weakness_id"), passport_meta.get("weakness_id"), nested(finding, "external_ids", "cwe"), nested(passport_meta, "external_ids", "cwe"), default=UNKNOWN),
        "weakness_type": first_value(finding.get("weakness_type"), passport_meta.get("weakness_type")),
        "location": first_value(finding.get("location"), passport_meta.get("location")),
        "os_platform": first_value(finding.get("os_platform"), wazuh_host_os.get("full"), host_meta.get("os"), default=UNKNOWN),
        "service_port_protocol": service_port_protocol_text(finding, passport_meta),
        "detection_method": detection_method(finding, passport_meta, software_vulnerability),
        "source": source,
        "severity": severity,
        "cvss_text": cvss_text(finding, software_vulnerability),
        "status": status,
        "description": first_value(finding.get("description"), profile_rule.get("rationale"), finding.get("title"), default=NO_DATA),
        "evidence": evidence_text(finding),
        "impact": first_value(finding.get("impact"), passport_meta.get("impact"), profile_rule.get("impact_ru"), default=NO_DATA),
        "remediation": first_value(finding.get("remediation"), profile_rule.get("remediation_ru"), profile_rule.get("remediation"), default=NO_DATA),
        "wazuh_index": first_value(wazuh_vulnerability.get("_index"), default=NO_DATA),
        "wazuh_document_id": first_value(wazuh_vulnerability.get("_id"), default=NO_DATA),
        "wazuh_agent_id": first_value(wazuh_agent.get("id"), default=NO_DATA),
        "wazuh_agent_name": first_value(wazuh_agent.get("name"), default=NO_DATA),
        "wazuh_agent_type": first_value(wazuh_agent.get("type"), default=NO_DATA),
        "wazuh_agent_version": first_value(wazuh_agent.get("version"), default=NO_DATA),
        "wazuh_host_os_full": first_value(wazuh_host_os.get("full"), default=NO_DATA),
        "wazuh_host_os_kernel": first_value(wazuh_host_os.get("kernel"), default=NO_DATA),
        "wazuh_host_os_name": first_value(wazuh_host_os.get("name"), default=NO_DATA),
        "wazuh_host_os_platform": first_value(wazuh_host_os.get("platform"), default=NO_DATA),
        "wazuh_host_os_type": first_value(wazuh_host_os.get("type"), default=NO_DATA),
        "wazuh_host_os_version": first_value(wazuh_host_os.get("version"), default=NO_DATA),
        "wazuh_package_architecture": first_value(nested(wazuh_vulnerability, "package", "architecture"), nested(finding, "affected_component", "architecture"), default=NO_DATA),
        "wazuh_package_description": first_value(nested(wazuh_vulnerability, "package", "description"), nested(finding, "affected_component", "description"), default=NO_DATA),
        "wazuh_package_name": first_value(nested(wazuh_vulnerability, "package", "name"), nested(finding, "affected_component", "package"), default=NO_DATA),
        "wazuh_package_size": first_value(nested(wazuh_vulnerability, "package", "size"), nested(finding, "affected_component", "size"), default=NO_DATA),
        "wazuh_package_type": first_value(nested(wazuh_vulnerability, "package", "type"), nested(finding, "affected_component", "type"), default=NO_DATA),
        "wazuh_package_version": first_value(nested(wazuh_vulnerability, "package", "version"), nested(finding, "affected_component", "version"), default=NO_DATA),
        "wazuh_vulnerability_category": first_value(wazuh_vuln.get("category"), default=NO_DATA),
        "wazuh_vulnerability_classification": first_value(wazuh_vuln.get("classification"), default=NO_DATA),
        "wazuh_vulnerability_description": first_value(wazuh_vuln.get("description"), finding.get("description"), default=NO_DATA),
        "wazuh_vulnerability_detected_at": first_value(wazuh_vuln.get("detected_at"), finding.get("detected_at"), default=NO_DATA),
        "wazuh_vulnerability_enumeration": first_value(wazuh_vuln.get("enumeration"), default=NO_DATA),
        "wazuh_scanner_condition": first_value(wazuh_scanner.get("condition"), default=NO_DATA),
        "wazuh_scanner_reference": first_value(wazuh_scanner.get("reference"), default=NO_DATA),
        "wazuh_scanner_source": first_value(wazuh_scanner.get("source"), default=NO_DATA),
        "wazuh_scanner_vendor": first_value(wazuh_scanner.get("vendor"), default=NO_DATA),
        "wazuh_score_base": first_value(wazuh_score.get("base"), cvss_score, default=NO_DATA),
        "wazuh_score_version": first_value(wazuh_score.get("version"), nested(finding, "cvss", "version"), default=NO_DATA),
        "wazuh_vulnerability_id": first_value(wazuh_vuln.get("id"), cve, default=NO_DATA),
        "wazuh_vulnerability_published_at": first_value(wazuh_vuln.get("published_at"), default=NO_DATA),
        "wazuh_vulnerability_reference": first_value(wazuh_vuln.get("reference"), references_text(references), default=NO_DATA),
        "wazuh_vulnerability_severity": first_value(wazuh_vuln.get("severity"), finding.get("severity"), default=NO_DATA),
        "wazuh_vulnerability_under_evaluation": first_value(wazuh_vuln.get("under_evaluation"), default=NO_DATA),
    }
    passport["passport_rows"] = passport_rows(passport)
    return passport


def build_passports(
    selected_findings: list[dict[str, Any]],
    profile_index: dict[str, dict[str, Any]],
    metadata: dict[str, Any],
    report_datetime: datetime,
) -> list[dict[str, Any]]:
    return [build_passport(finding, index, profile_index, metadata, report_datetime) for index, finding in enumerate(selected_findings, start=1)]


def build_normalized_report_for_export(
    source_findings: list[dict[str, Any]],
    filtered_findings: list[dict[str, Any]],
    metadata: dict[str, Any],
    report_id: str,
    profile: str | None = None,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    policy_options = metadata.get("policy_options") if isinstance(metadata.get("policy_options"), dict) else {}
    return build_normalized_report(
        source_findings,
        filtered_findings=filtered_findings,
        metadata=metadata,
        policy_options=policy_options,
        profile=profile,
        report_id=report_id,
        generated_at=generated_at,
    )


def render_export_files(
    normalized_report: dict[str, Any],
    json_path: Path,
    html_path: Path,
    pdf_path: Path | None = None,
) -> list[str]:
    render_technical_json(normalized_report, json_path)
    render_technical_html(normalized_report, html_path)
    written = [str(json_path), str(html_path)]
    if pdf_path is not None:
        render_technical_pdf(html_path, pdf_path)
        written.append(str(pdf_path))
    return written
