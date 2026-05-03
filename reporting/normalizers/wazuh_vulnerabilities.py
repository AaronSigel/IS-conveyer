from __future__ import annotations

from typing import Any


def normalize_severity(value: Any) -> str:
    mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}
    return mapping.get((value or "").strip().lower(), "medium")


def split_references(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [part.strip() for part in str(value).split(",") if part.strip()]


def cvss_severity(score: float | None) -> str | None:
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


def vulnerability_rule_id(cve_id: str, package_name: str) -> str:
    package_part = str(package_name or "unknown-package").strip().lower() or "unknown-package"
    return f"{cve_id}:{package_part}"


def vulnerability_title(cve_id: str, package: dict[str, Any]) -> str:
    package_name = package.get("name") or "unknown package"
    package_description = package.get("description")
    if package_description:
        return f"{cve_id} in {package_name} ({package_description})"
    return f"{cve_id} in {package_name}"


def vulnerability_remediation(package_name: str, cve_id: str, scanner: dict[str, Any], rule_meta: dict[str, Any] | None) -> str:
    if rule_meta and rule_meta.get("remediation"):
        return rule_meta["remediation"]
    condition = scanner.get("condition")
    if condition:
        return f"Update {package_name} to a package version that satisfies the Wazuh scanner condition: {condition}."
    return f"Update {package_name} to a version that is not affected by {cve_id}."


def vulnerability_detection_method(scanner: dict[str, Any]) -> str:
    parts = ["Wazuh Vulnerability Detector"]
    source = scanner.get("source")
    vendor = scanner.get("vendor")
    if source:
        parts.append(str(source))
    if vendor and vendor not in parts:
        parts.append(str(vendor))
    return " / ".join(parts)


def normalize_vulnerability_findings(vulnerability_hits: list[dict[str, Any]], targets: tuple[str, ...], vulnerability_rules: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for hit in vulnerability_hits:
        source = hit.get("_source", {})
        agent = source.get("agent", {})
        host_os = source.get("host", {}).get("os", {})
        vulnerability = source.get("vulnerability", {})
        scanner = vulnerability.get("scanner", {}) if isinstance(vulnerability.get("scanner"), dict) else {}
        package = source.get("package", {})
        host = agent.get("name")
        if host not in targets:
            continue

        package_name = package.get("name", "unknown-package")
        package_version = package.get("version", "unknown-version")
        cve_id = str(vulnerability.get("id", hit.get("_id", "unknown-vulnerability"))).upper()
        rule_meta = vulnerability_rules.get(cve_id)

        evidence = [f"Package: {package_name} {package_version}", f"CVE: {cve_id}"]
        if package.get("architecture"):
            evidence.append(f"Architecture: {package['architecture']}")
        if package.get("type"):
            evidence.append(f"Package type: {package['type']}")
        if vulnerability.get("severity"):
            evidence.append(f"Severity: {vulnerability['severity']}")

        cvss: dict[str, Any] = {}
        if vulnerability.get("score", {}).get("base") is not None:
            cvss["base_score"] = vulnerability["score"]["base"]
            evidence.append(f"CVSS base: {vulnerability['score']['base']}")
        elif rule_meta and rule_meta["cvss"].get("base_score") is not None:
            cvss["base_score"] = rule_meta["cvss"]["base_score"]
            evidence.append(f"CVSS base: {rule_meta['cvss']['base_score']}")
        if vulnerability.get("score", {}).get("vector"):
            cvss["vector"] = vulnerability["score"]["vector"]
        elif rule_meta and rule_meta["cvss"].get("vector"):
            cvss["vector"] = rule_meta["cvss"]["vector"]
        if vulnerability.get("score", {}).get("version"):
            cvss["version"] = str(vulnerability["score"]["version"])

        if vulnerability.get("published_at"):
            evidence.append(f"Published: {vulnerability['published_at']}")
        if vulnerability.get("detected_at"):
            evidence.append(f"Detected: {vulnerability['detected_at']}")
        if vulnerability.get("classification"):
            evidence.append(f"Classification: {vulnerability['classification']}")
        if scanner.get("condition"):
            evidence.append(f"Scanner condition: {scanner['condition']}")

        references = split_references(vulnerability.get("reference"))
        if scanner.get("reference"):
            references.append(str(scanner["reference"]))

        severity = normalize_severity(vulnerability.get("severity") or (rule_meta or {}).get("severity"))
        if not vulnerability.get("severity") and cvss.get("base_score") is not None:
            severity = cvss_severity(float(cvss["base_score"]))

        structured_vulnerability = {
            "_index": hit.get("_index"),
            "_id": hit.get("_id"),
            "agent": dict(agent),
            "host": {"os": dict(host_os)},
            "package": dict(package),
            "vulnerability": dict(vulnerability),
        }

        finding: dict[str, Any] = {
            "host": host,
            "source": "wazuh-indexer-vulnerabilities",
            "category": "vulnerability",
            "rule_id": vulnerability_rule_id(cve_id, package_name),
            "title": vulnerability_title(cve_id, package),
            "severity": severity,
            "status": "fail",
            "evidence": evidence,
            "remediation": vulnerability_remediation(package_name, cve_id, scanner, rule_meta),
            "finding_type": "software_vulnerability",
            "external_ids": {"cve": cve_id},
            "vulnerability_id": cve_id,
            "cve": cve_id,
            "affected_component": {
                "name": package_name,
                "package": package_name,
                "version": package_version,
                "architecture": package.get("architecture"),
                "description": package.get("description"),
                "size": package.get("size"),
                "type": package.get("type"),
            },
            "description": vulnerability.get("description"),
            "detected_at": vulnerability.get("detected_at"),
            "os_platform": host_os.get("full") or host_os.get("platform"),
            "detection_method": vulnerability_detection_method(scanner),
            "references": references,
            "wazuh_vulnerability": structured_vulnerability,
        }
        if cvss:
            finding["cvss"] = cvss
        findings.append(finding)
    return findings


def build_vulnerability_pass_findings(targets: tuple[str, ...], vulnerability_rules: dict[str, dict[str, Any]], failed_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    failed_keys = {(finding["host"], finding["rule_id"]) for finding in failed_findings if finding.get("status") == "fail"}
    findings: list[dict[str, Any]] = []
    for host in targets:
        for rule_meta in vulnerability_rules.values():
            if (host, rule_meta["rule_id"]) in failed_keys:
                continue

            packages = sorted(rule_meta["packages"])
            evidence = [f"CVE: {rule_meta['cve']}", "No matching Wazuh vulnerability state found for this host and rule."]
            if rule_meta["cvss"].get("base_score") is not None:
                evidence.append(f"CVSS base: {rule_meta['cvss']['base_score']}")
            if packages:
                evidence.append(f"Package: {', '.join(packages)}")

            affected_component = {}
            if packages:
                affected_component["package"] = ", ".join(packages)

            finding: dict[str, Any] = {
                "host": host,
                "source": "wazuh-indexer-vulnerabilities",
                "category": "vulnerability",
                "rule_id": rule_meta["rule_id"],
                "title": rule_meta["title"],
                "severity": rule_meta["severity"],
                "status": "pass",
                "evidence": evidence,
                "remediation": rule_meta["remediation"],
                "finding_type": "software_vulnerability",
                "external_ids": {"cve": rule_meta["cve"]},
                "cve": rule_meta["cve"],
            }
            if rule_meta["cvss"]:
                finding["cvss"] = rule_meta["cvss"]
            if affected_component:
                finding["affected_component"] = affected_component
            findings.append(finding)
    return findings
