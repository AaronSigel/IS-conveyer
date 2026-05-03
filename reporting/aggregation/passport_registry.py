from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Any

from reporting.common import severity_rank, stable_id, unique_sorted
from reporting.text_normalization import limit_summary_text, normalize_whitespace


NO_SOURCE = "не установлено по данным источника"
NOT_APPLICABLE = "не применимо"
MANUAL_REVIEW = "требует ручного уточнения"


PRIORITY_ORDER = {"P1": 4, "P2": 3, "P3": 2, "P4": 1}


def _text(value: Any, default: str = NO_SOURCE) -> str:
    if value in (None, "", [], {}):
        return default
    return str(value)


def _asset_record(assets: list[dict[str, Any]], asset_name: str | None) -> dict[str, Any]:
    for asset in assets:
        if asset.get("agent.name") == asset_name or asset.get("agent_name") == asset_name:
            return asset
    return {}


def _asset_os(asset: dict[str, Any], fallback: dict[str, Any] | None = None) -> tuple[str, str]:
    fallback = fallback or {}
    os_name = asset.get("os_name") or asset.get("host.os.full") or fallback.get("full") or fallback.get("name")
    platform = asset.get("architecture") or asset.get("host.architecture") or fallback.get("architecture")
    return _text(os_name), _text(platform)


def _fixed_version(condition: Any) -> str:
    text = str(condition or "").strip()
    lower = text.lower()
    if "less than" in lower:
        return text[lower.index("less than") + len("less than") :].strip().rstrip(".")
    if text and text not in {"not provided", "Package default status"}:
        return text
    return "исправленная версия не указана источником; требуется установка актуального security update"


def _package_title(finding: dict[str, Any]) -> tuple[str, str]:
    cve = _text(finding.get("cve"))
    package = _text(finding.get("package", {}).get("name"))
    return f"Уязвимость {cve} в пакете {package}", f"{cve} vulnerability in package {package}"


def _configuration_title(group: dict[str, Any]) -> tuple[str, str]:
    title = str(group.get("title") or "")
    if group.get("title_ru"):
        return str(group["title_ru"]), title or "Configuration hardening finding"
    mapping = {
        "Configure AIDE integrity monitoring": "Настройка контроля целостности AIDE",
        "Configure time synchronization": "Настройка синхронизации времени",
        "Ensure bootloader password is set": "Настройка пароля загрузчика GRUB",
        "Ensure ftp client is not installed": "Наличие FTP-клиента",
        "Ensure rsync services are not in use": "Использование службы rsync",
        "Harden sshd_config": "Недостаточная настройка параметров безопасности SSH-сервера",
        "Configure PAM password and lockout policy": "Недостаточная настройка политики аутентификации PAM",
        "Choose and configure a single firewall backend": "Неполная настройка межсетевого экранирования хоста",
        "Configure nftables firewall backend": "Неполная настройка межсетевого экранирования хоста",
        "Configure UFW firewall backend": "Неполная настройка межсетевого экранирования хоста",
        "Configure iptables firewall backend": "Неполная настройка межсетевого экранирования хоста",
        "Configure auditd and audit rules": "Недостаточная настройка подсистемы аудита auditd",
        "Configure audit rules for locale and network changes": "Настройка аудита изменений локали и сети",
        "Configure AppArmor mandatory access control": "Недостаточная настройка мандатного контроля доступа AppArmor",
        "Disable unused kernel modules": "Доступность неиспользуемых модулей ядра",
        "Remove insecure clients and services": "Наличие небезопасных клиентских программ и сервисов",
        "Harden temporary filesystems": "Недостаточные параметры безопасности временных файловых систем",
        "Separate and harden system log/data partitions": "Недостаточная изоляция системных разделов и журналов",
        "Configure system logging": "Недостаточная настройка системного журналирования",
    }
    return mapping.get(title, title or "Недостаточная настройка параметров безопасности хоста"), title or "Configuration hardening finding"


def _configuration_component(group: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    action_key = str(group.get("action_key") or "")
    component_by_action = {
        "bootloader": "GRUB bootloader",
        "ftp_client": "FTP client package",
        "rsync_service": "rsync service/package",
        "login_banners": "login banners",
        "audit_locale_network": "auditd",
        "cron_at": "cron and at access control",
        "kernel_modules": "Linux kernel modules",
        "insecure_services": "legacy network clients and services",
        "aide": "AIDE integrity monitoring",
        "time_sync": "time synchronization service",
        "core_dumps": "core dump handling",
        "logging": "system logging",
    }
    if action_key.startswith("firewall:"):
        return "Host firewall"
    if action_key in component_by_action:
        return component_by_action[action_key]
    title = str(group.get("title") or "").lower()
    if "ssh" in title:
        return "OpenSSH server"
    if "pam" in title or "password" in title:
        return "PAM authentication stack"
    if "firewall" in title or "ufw" in title or "nftables" in title or "iptables" in title:
        return "Host firewall"
    if "audit" in title:
        return "auditd"
    if "apparmor" in title:
        return "AppArmor"
    if "kernel" in title:
        return "Linux kernel modules"
    subsystems = unique_sorted([item.get("subsystem") for item in findings])
    return ", ".join(subsystems) if subsystems else "Host configuration"


def _configuration_location(group: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    action_key = str(group.get("action_key") or "")
    location_by_action = {
        "bootloader": "/boot/grub/grub.cfg, /etc/grub.d/*, /etc/default/grub",
        "ftp_client": "installed packages ftp/tnftp",
        "rsync_service": "rsync package and rsync.service",
        "login_banners": "/etc/issue, /etc/issue.net, sshd Banner",
        "audit_locale_network": "/etc/audit/rules.d/50-system_locale.rules, auditctl rules",
        "cron_at": "/etc/cron.*, /etc/at.allow, /etc/at.deny",
        "kernel_modules": "/etc/modprobe.d/*, lsmod, module denylist",
        "insecure_services": "installed packages and services telnet/rsh/nis/talk",
        "aide": "/etc/aide/*, /var/lib/aide/*, dailyaidecheck.timer",
        "time_sync": "chrony/systemd-timesyncd service configuration",
        "core_dumps": "/etc/systemd/coredump.conf, /etc/security/limits.conf, sysctl",
        "logging": "systemd-journald and logging configuration",
    }
    if action_key.startswith("firewall:"):
        backend = action_key.split(":", 1)[1]
        return {
            "ufw": "ufw ruleset and service configuration",
            "nftables": "nftables ruleset and service configuration",
            "iptables": "iptables/ip6tables ruleset",
            "choose": "selected host firewall backend configuration",
        }.get(backend, "host firewall configuration")
    if action_key in location_by_action:
        return location_by_action[action_key]
    text = " ".join([str(group.get("title") or ""), *(str(item.get("check", {}).get("command") or "") for item in findings)])
    lowered = text.lower()
    if "ssh" in lowered or "sshd" in lowered:
        return "/etc/ssh/sshd_config, /etc/ssh/sshd_config.d/*"
    if "pam" in lowered or "faillock" in lowered or "pwquality" in lowered:
        return "/etc/pam.d/*, /etc/security/*"
    if "audit" in lowered:
        return "/etc/audit/auditd.conf, /etc/audit/rules.d/*"
    if "apparmor" in lowered:
        return "/etc/apparmor.d/*, bootloader kernel parameters"
    if "ufw" in lowered:
        return "ufw ruleset and service configuration"
    if "nft" in lowered:
        return "nftables ruleset and service configuration"
    if "iptables" in lowered:
        return "iptables/ip6tables ruleset"
    if "/var/log/audit" in lowered:
        return "/var/log/audit"
    if "/var/log" in lowered:
        return "/var/log"
    if "/var/tmp" in lowered:
        return "/var/tmp"
    if "/tmp" in lowered:
        return "/tmp"
    if "/home" in lowered:
        return "/home"
    commands = unique_sorted([item.get("check", {}).get("command") for item in findings if item.get("check", {}).get("command")])
    return ", ".join(commands[:3]) if commands else MANUAL_REVIEW


def _expected_state_human(group: dict[str, Any], component: str) -> str:
    action_key = str(group.get("action_key") or "")
    base_key = "firewall" if action_key.startswith("firewall:") else action_key
    mapping = {
        "ssh": "Параметры SSH-сервера соответствуют выбранному профилю безопасности CIS.",
        "pam": "Включены требования к сложности пароля, истории паролей и блокировке после неуспешных попыток входа.",
        "aide": "Пакет AIDE установлен, база инициализирована, периодическая проверка целостности включена.",
        "auditd": "Служба auditd активна, правила аудита загружены и сохраняются после перезагрузки.",
        "audit_locale_network": "Изменения системной локали, hostname, hosts и сетевой конфигурации регистрируются правилами auditd.",
        "firewall": "Активен один выбранный backend межсетевого экранирования, конфликтующие backend'ы не используются.",
        "apparmor": "AppArmor установлен, активен при загрузке и применяет требуемые профили.",
        "bootloader": "Загрузчик GRUB защищен паролем, изменение параметров загрузки доступно только уполномоченным администраторам.",
        "ftp_client": "FTP-клиенты ftp/tnftp не установлены, если нет утвержденного исключения.",
        "rsync_service": "Служба rsync отключена или отсутствует, если она не требуется роли хоста.",
        "login_banners": "Локальные и удаленные баннеры входа соответствуют утвержденному тексту и не раскрывают сведения о системе.",
        "cron_at": "Доступ к cron и at ограничен разрешенными администраторами, allow/deny-файлы имеют безопасные права.",
        "kernel_modules": "Неиспользуемые или небезопасные модули ядра запрещены через modprobe и не загружены.",
        "insecure_services": "Небезопасные legacy-клиенты и сервисы не установлены или отключены.",
        "time_sync": "Используется один утвержденный сервис синхронизации времени, система синхронизирована с доверенным источником.",
        "core_dumps": "Core dump отключены или ограничены политикой, исключающей утечку чувствительных данных.",
        "logging": "Системное журналирование включено, устойчиво к перезагрузке и соответствует профилю безопасности.",
    }
    return mapping.get(base_key, f"{component} соответствует выбранному профилю безопасности CIS.")


def _weakness_for_configuration(component: str, group: dict[str, Any]) -> str:
    title = str(group.get("title") or "").lower()
    if "install" in title or "remove" in title or "package" in title:
        return "избыточный установленный компонент"
    if "firewall" in title or "apparmor" in title or "audit" in title:
        return "отсутствие или неполная настройка защитного механизма"
    if "mount" in title or "kernel" in title or "ssh" in title or "pam" in title:
        return "небезопасное значение параметра"
    return "неправильная настройка параметров ПО"


def _verification_steps(group_or_finding: dict[str, Any]) -> list[dict[str, Any]]:
    steps = group_or_finding.get("verification") or group_or_finding.get("verification_steps") or []
    normalized: list[dict[str, Any]] = []
    for item in steps:
        if isinstance(item, dict):
            command = str(item.get("command") or "").strip()
            if not command:
                continue
            expected = str(item.get("expected_result") or "").strip()
            if expected == "Command output matches the remediation target":
                expected = "повторная проверка подтверждает безопасное состояние"
            normalized.append({**item, "command": command, "expected_result": expected or "повторная проверка подтверждает безопасное состояние"})
    return normalized


def _score(passport: dict[str, Any], required: list[str]) -> tuple[float, str]:
    total = len(required)
    present = 0
    for key in required:
        value = passport.get(key)
        if value in (None, "", [], {}):
            continue
        if value == MANUAL_REVIEW:
            continue
        present += 1
    score = round(present / total, 2) if total else 1.0
    return score, "complete" if score >= 0.9 else "incomplete"


def _is_missing(value: Any) -> bool:
    return value in (None, "", [], {}, NO_SOURCE, MANUAL_REVIEW, "not provided", "unknown")


def _score_fields(passport: dict[str, Any], fields: list[str]) -> float:
    if not fields:
        return 1.0
    present = sum(1 for key in fields if not _is_missing(passport.get(key)))
    return round(present / len(fields), 2)


def _missing_fields(passport: dict[str, Any], fields: list[str]) -> list[str]:
    return [key for key in fields if _is_missing(passport.get(key))]


def _finalize(passport: dict[str, Any], required: list[str], extended: list[str] | None = None) -> dict[str, Any]:
    for key, value in list(passport.items()):
        if value in (None, ""):
            passport[key] = NO_SOURCE
    score, status = _score(passport, required)
    extended = extended or []
    extended_score = _score_fields(passport, extended)
    missing_extended = _missing_fields(passport, extended)
    passport["completeness_score"] = score
    passport["passport_completeness_score"] = score
    passport["mandatory_completeness"] = score
    passport["extended_completeness"] = extended_score
    passport["missing_extended_fields"] = missing_extended
    passport["completeness_status"] = status
    passport["completeness_note"] = (
        "обязательные поля заполнены"
        if not missing_extended
        else "источник не содержит: " + ", ".join(missing_extended[:6])
    )
    return passport


def _package_passport(finding: dict[str, Any], assets: list[dict[str, Any]]) -> dict[str, Any]:
    asset_name = next(iter(finding.get("affected_assets", []) or []), None)
    asset = _asset_record(assets, asset_name)
    os_name, platform = _asset_os(asset, finding.get("os") if isinstance(finding.get("os"), dict) else {})
    package = finding.get("package", {}) if isinstance(finding.get("package"), dict) else {}
    severity = finding.get("severity", {}) if isinstance(finding.get("severity"), dict) else {}
    detection = finding.get("detection", {}) if isinstance(finding.get("detection"), dict) else {}
    title_ru, title_en = _package_title(finding)
    cve = _text(finding.get("cve"))
    description_full = normalize_whitespace(_text(finding.get("description")))
    description_short = limit_summary_text(description_full, 700)
    verification = _verification_steps(finding)
    if not verification:
        verification = [{"command": "repeat Wazuh vulnerability scan", "expected_result": "повторное сканирование Wazuh не выявляет данную CVE", "manual": True, "requires_root": False, "safe_to_run": True, "notes": ""}]
    passport = {
        "passport_id": stable_id("VP-CVE", cve, asset_name, package.get("name"), package.get("installed_version")),
        "passport_type": "software",
        "finding_refs": [finding.get("finding_uid")],
        "raw_refs": finding.get("raw_refs", []),
        "title_ru": title_ru,
        "title_en": title_en,
        "vulnerability_class": "уязвимость кода",
        "weakness_type": NO_SOURCE,
        "object": _text(asset_name),
        "asset": _text(asset_name),
        "component": _text(package.get("name")),
        "software_name": _text(package.get("name")),
        "software_version": _text(package.get("installed_version")),
        "fixed_version": _fixed_version(package.get("fixed_condition")),
        "architecture": _text(package.get("architecture")),
        "os": os_name,
        "platform": platform,
        "location": "установленный пакет",
        "detection_method": "Wazuh Vulnerability Detection, сопоставление версии пакета с CVE-базой",
        "source": _text(detection.get("source"), "Wazuh Vulnerability Detection"),
        "actual_state": f"Установлен пакет {package.get('name')} версии {package.get('installed_version')}",
        "expected_state": f"Пакет обновлён до исправленной версии: {_fixed_version(package.get('fixed_condition'))}",
        "expected_state_human": f"Пакет обновлен до исправленной версии: {_fixed_version(package.get('fixed_condition'))}",
        "expected_state_raw": _text(package.get("fixed_condition")),
        "description": description_short,
        "description_short": description_short,
        "description_full": description_full,
        "conditions": _text(detection.get("scanner_condition")),
        "severity": _text(severity.get("level"), "info"),
        "priority": _text(finding.get("priority"), "P4"),
        "cvss_score": severity.get("score") if severity.get("score") not in (None, -1) else NO_SOURCE,
        "cvss_vector": _text(severity.get("vector"), NO_SOURCE),
        "external_ids": {"cve": cve},
        "consequences": _text(finding.get("impact"), "возможна эксплуатация уязвимости установленного программного компонента"),
        "security_impact": _text(finding.get("impact"), "снижение защищенности хоста из-за уязвимого программного компонента"),
        "remediation_summary": "Обновить затронутый пакет до исправленной версии или актуального security update",
        "remediation_steps": [f"Обновить пакет {package.get('name')} штатным пакетным менеджером ОС"],
        "verification_steps": verification,
        "status": _text(finding.get("status"), "fail"),
        "detected_at": ", ".join(detection.get("detected_at") or []) or NO_SOURCE,
        "references": finding.get("references", []),
        "linked_checks": [],
    }
    required = [
        "passport_id", "title_ru", "vulnerability_class", "asset", "component", "location", "detection_method",
        "severity", "remediation_summary", "verification_steps", "source", "status", "external_ids",
        "software_name", "software_version",
    ]
    extended = ["fixed_version", "cvss_score", "cvss_vector", "references", "description_full"]
    return _finalize(passport, required, extended)


def _configuration_passport(group: dict[str, Any], finding_by_uid: dict[str, dict[str, Any]], assets: list[dict[str, Any]]) -> dict[str, Any]:
    findings = [finding_by_uid[uid] for uid in group.get("affected_findings", []) if uid in finding_by_uid]
    asset_name = next(iter(group.get("affected_assets", []) or []), None)
    asset = _asset_record(assets, asset_name)
    os_name, platform = _asset_os(asset)
    title_ru, title_en = _configuration_title(group)
    component = _configuration_component(group, findings)
    location = _configuration_location(group, findings)
    actual_values = unique_sorted([item.get("check", {}).get("actual") for item in findings])
    expected_values = unique_sorted([item.get("check", {}).get("expected") for item in findings])
    expected_raw = "; ".join(expected_values) if expected_values else NO_SOURCE
    expected_human = _expected_state_human(group, component)
    description_full = normalize_whitespace(_text(group.get("summary")))
    description_short = limit_summary_text(description_full, 700)
    checks = [
        {
            "id": item.get("requirement", {}).get("id"),
            "title": item.get("requirement", {}).get("title") or item.get("title"),
            "command": item.get("check", {}).get("command"),
        }
        for item in findings
    ]
    verification = _verification_steps(group)
    passport = {
        "passport_id": stable_id("VP-CFG", group.get("group_id") or group.get("title")),
        "passport_type": "configuration",
        "finding_refs": list(group.get("affected_findings", [])),
        "raw_refs": [raw for item in findings for raw in item.get("raw_refs", [])],
        "title_ru": title_ru,
        "title_en": title_en,
        "vulnerability_class": "уязвимость конфигурации",
        "weakness_type": _weakness_for_configuration(component, group),
        "object": ", ".join(group.get("affected_assets", [])) or NO_SOURCE,
        "asset": ", ".join(group.get("affected_assets", [])) or NO_SOURCE,
        "component": component,
        "software_name": NOT_APPLICABLE,
        "software_version": NOT_APPLICABLE,
        "fixed_version": NOT_APPLICABLE,
        "architecture": _text(asset.get("architecture") or asset.get("host.architecture")),
        "os": os_name,
        "platform": platform,
        "location": location,
        "detection_method": "Wazuh SCA, CIS Ubuntu 24.04 policy, команда проверки",
        "source": "Wazuh SCA",
        "actual_state": "; ".join(actual_values) if actual_values else NO_SOURCE,
        "expected_state": expected_human,
        "expected_state_human": expected_human,
        "expected_state_raw": expected_raw,
        "description": description_short,
        "description_short": description_short,
        "description_full": description_full,
        "conditions": _text("; ".join(unique_sorted([item.get("check", {}).get("command") for item in findings])), NO_SOURCE),
        "severity": _text(group.get("severity_max"), "info"),
        "priority": _text(group.get("priority"), "P4"),
        "cvss_score": NOT_APPLICABLE,
        "cvss_vector": NOT_APPLICABLE,
        "external_ids": {"cis": unique_sorted([item.get("requirement", {}).get("id") for item in findings])},
        "consequences": _text("; ".join(unique_sorted([item.get("impact") for item in findings])), "повышение риска нарушения защищенности хоста"),
        "security_impact": _text("; ".join(unique_sorted([item.get("impact") for item in findings])), "повышение риска нарушения защищенности хоста"),
        "remediation_summary": _text(group.get("summary")),
        "remediation_steps": list(group.get("commands", [])) or [_text(group.get("summary"))],
        "verification_steps": verification,
        "status": "fail",
        "detected_at": NO_SOURCE,
        "references": [item.get("references") for item in findings if item.get("references")],
        "linked_checks": checks,
    }
    required = [
        "passport_id", "title_ru", "vulnerability_class", "asset", "component", "location", "detection_method",
        "severity", "remediation_summary", "verification_steps", "source", "status", "actual_state",
        "expected_state_human",
    ]
    extended = ["expected_state_raw", "linked_checks", "references", "description_full"]
    return _finalize(passport, required, extended)


def _package_group_passport(group: dict[str, Any], assets: list[dict[str, Any]]) -> dict[str, Any]:
    package = group.get("package", {}) if isinstance(group.get("package"), dict) else {}
    asset_name = str(group.get("asset") or next(iter(group.get("affected_assets", []) or []), "unknown"))
    asset = _asset_record(assets, asset_name)
    os_name, platform = _asset_os(asset)
    package_name = _text(package.get("name"))
    vulnerabilities = group.get("vulnerabilities") if isinstance(group.get("vulnerabilities"), list) else []
    top_vulnerabilities = vulnerabilities[:5]
    cve_ids = [str(item.get("id")) for item in top_vulnerabilities if item.get("id")]
    max_cvss = group.get("max_cvss")
    fixed_versions = unique_sorted([item.get("fixed_version") for item in vulnerabilities if item.get("fixed_version")])
    fixed_text = fixed_versions[0] if fixed_versions else "исправленная версия не указана источником; требуется установка актуального security update"
    title = f"Группа уязвимостей пакета {package_name}"
    description = (
        f"В пакете {package_name} выявлено {len(vulnerabilities)} CVE. "
        f"Максимальная критичность: {group.get('severity_max', 'info')}. "
        f"Ключевые CVE: {', '.join(cve_ids) if cve_ids else 'перечень доступен в passport_registry.html'}."
    )
    verification = _verification_steps(group) or [
        {
            "command": "repeat Wazuh vulnerability scan",
            "expected_result": "повторное сканирование Wazuh Vulnerability Detection не выявляет CVE по данному пакету",
            "manual": True,
            "requires_root": False,
            "safe_to_run": True,
            "notes": "",
        }
    ]
    passport = {
        "passport_id": stable_id("VP-PKG-GRP", group.get("group_id"), package_name, asset_name),
        "passport_type": "software_group",
        "finding_refs": list(group.get("affected_findings", [])),
        "raw_refs": [],
        "title_ru": title,
        "title_en": f"Vulnerability group for package {package_name}",
        "vulnerability_class": "уязвимость кода",
        "weakness_type": NO_SOURCE,
        "object": asset_name,
        "asset": asset_name,
        "component": package_name,
        "software_name": package_name,
        "software_version": _text(package.get("version")),
        "fixed_version": fixed_text,
        "architecture": _text(package.get("architecture")),
        "os": os_name,
        "platform": platform,
        "location": "установленный пакет",
        "detection_method": "Wazuh Vulnerability Detection, агрегация CVE по пакету",
        "source": "Wazuh Vulnerability Detection",
        "actual_state": f"Установлен пакет {package_name} версии {package.get('version')}",
        "expected_state": f"Пакет обновлен до исправленной версии или актуального security update: {fixed_text}",
        "expected_state_human": f"Пакет обновлен до исправленной версии или актуального security update: {fixed_text}",
        "expected_state_raw": ", ".join(fixed_versions) if fixed_versions else NO_SOURCE,
        "description": limit_summary_text(description, 700),
        "description_short": limit_summary_text(description, 700),
        "description_full": description,
        "conditions": "Полный перечень CVE и условий сканера доступен в passport_registry.html.",
        "severity": _text(group.get("severity_max"), "info"),
        "priority": _text(group.get("priority"), "P4"),
        "cvss_score": max_cvss if max_cvss not in (None, "") else NO_SOURCE,
        "cvss_vector": NO_SOURCE,
        "external_ids": {"cve": cve_ids, "cve_count": len(vulnerabilities)},
        "consequences": "снижение защищенности хоста из-за группы уязвимостей установленного программного компонента",
        "security_impact": "снижение защищенности хоста из-за группы уязвимостей установленного программного компонента",
        "remediation_summary": "Обновить пакет до исправленной версии или актуального security update; для ядра выполнить перезагрузку при необходимости",
        "remediation_steps": list(group.get("commands", [])) or [f"Обновить пакет {package_name} штатным пакетным менеджером ОС"],
        "verification_steps": verification,
        "status": "fail",
        "detected_at": NO_SOURCE,
        "references": [],
        "linked_checks": [],
    }
    required = [
        "passport_id", "title_ru", "vulnerability_class", "asset", "component", "location", "detection_method",
        "severity", "remediation_summary", "verification_steps", "source", "status", "external_ids",
        "software_name", "software_version",
    ]
    extended = ["fixed_version", "cvss_score", "description_full"]
    return _finalize(passport, required, extended)


def build_vulnerability_passports(
    findings: list[dict[str, Any]],
    remediation_groups: list[dict[str, Any]],
    assets: list[dict[str, Any]],
    options: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    finding_by_uid = {item.get("finding_uid"): item for item in findings if item.get("finding_uid")}
    passports: list[dict[str, Any]] = []
    for group in remediation_groups:
        if group.get("action_type") == "package_update":
            passports.append(_package_group_passport(group, assets))
    for finding in findings:
        if finding.get("type") == "software_vulnerability":
            passports.append(_package_passport(finding, assets))
    covered_config_findings: set[str] = set()
    for group in remediation_groups:
        if group.get("action_type") == "config_change":
            passports.append(_configuration_passport(group, finding_by_uid, assets))
            covered_config_findings.update(str(uid) for uid in group.get("affected_findings", []) if uid)
    for finding in findings:
        uid = str(finding.get("finding_uid") or "")
        if finding.get("type") == "configuration_noncompliance" and uid and uid not in covered_config_findings:
            pseudo_group = {
                "group_id": stable_id("REM-CFG-EXC", uid),
                "title": finding.get("title") or "Configuration finding outside remediation plan",
                "summary": finding.get("remediation", {}).get("summary") or finding.get("description") or "Configuration finding requires review",
                "severity_max": finding.get("severity", {}).get("level", "info"),
                "priority": finding.get("priority", "P4"),
                "affected_assets": finding.get("affected_assets", []),
                "affected_findings": [uid],
                "verification": finding.get("remediation", {}).get("verification") or [],
                "commands": finding.get("remediation", {}).get("commands") or [],
            }
            passports.append(_configuration_passport(pseudo_group, finding_by_uid, assets))

    passport_by_finding: dict[str, list[str]] = defaultdict(list)
    for passport in passports:
        for uid in passport.get("finding_refs", []):
            passport_by_finding[uid].append(passport["passport_id"])
    for finding in findings:
        finding["passport_refs"] = passport_by_finding.get(finding.get("finding_uid"), [])
    for group in remediation_groups:
        refs = unique_sorted([ref for uid in group.get("affected_findings", []) for ref in passport_by_finding.get(uid, [])])
        group["passport_refs"] = refs
    return sorted(passports, key=lambda item: (-PRIORITY_ORDER.get(item.get("priority", "P4"), 0), -severity_rank(item.get("severity")), item.get("title_ru", "")))


def build_passport_matrix() -> list[dict[str, str]]:
    return [
        {"field": "Идентификатор уязвимости", "automatic": "да", "source": "CVE/Wazuh vulnerability.id или generated passport_id", "comment": "Для конфигурации формируется стабильный идентификатор паспорта."},
        {"field": "Наименование уязвимости", "automatic": "частично", "source": "CVE title/enrichment/rule title/remediation group", "comment": "Русское наименование формируется по типу finding."},
        {"field": "Класс уязвимости", "automatic": "да", "source": "классификатор проекта", "comment": "ПО: уязвимость кода; SCA: уязвимость конфигурации."},
        {"field": "ПО и версия", "automatic": "да", "source": "package.name/package.version или SCA component", "comment": "Для конфигурации поле помечается как неприменимое."},
        {"field": "Место возникновения", "automatic": "частично", "source": "package/component/config path/check command", "comment": "Для ряда SCA-групп путь выводится из локального классификатора."},
        {"field": "Способ обнаружения", "automatic": "да", "source": "Wazuh Vulnerability Detection или Wazuh SCA", "comment": "Включает метод сопоставления версий или SCA-команду."},
        {"field": "Степень опасности", "automatic": "да", "source": "Wazuh severity/CVSS/severity policy", "comment": "Приоритет P1-P4 считается pipeline."},
        {"field": "Возможные последствия", "automatic": "частично", "source": "Wazuh description/rationale/project knowledge base", "comment": "При отсутствии данных используется явная отметка ограничения источника."},
        {"field": "Меры устранения", "automatic": "да", "source": "remediation rules/package update rules", "comment": "Детальные команды доступны в remediation groups и registry."},
        {"field": "Статус обработки", "automatic": "да", "source": "pipeline status/applicability", "comment": "Exceptions и under evaluation отделяются от плана устранения."},
    ]


def select_summary_passports(
    passports: list[dict[str, Any]],
    remediation_plan: list[dict[str, Any]],
    options: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    options = options or {}
    if str(options.get("passport_scope") or "top") == "all":
        return passports
    max_items = int(options.get("max_summary_passports") or 25)
    max_software = int(options.get("max_summary_software_passports") or 10)
    max_cve_per_package = int(options.get("max_summary_cve_per_package") or 5)
    min_priority = str(options.get("min_passport_priority") or "P2").upper()
    include_low = bool(options.get("include_low", False))
    include_info = bool(options.get("include_info", False))
    top_refs = {ref for group in remediation_plan[: max_items] for ref in group.get("passport_refs", [])}
    threshold = PRIORITY_ORDER.get(min_priority, PRIORITY_ORDER["P2"])
    strong_packages = {
        str(passport.get("component") or passport.get("software_name") or "")
        for passport in passports
        if passport.get("passport_type") == "software" and str(passport.get("severity") or "").lower() in {"critical", "high"}
    }
    software_count = 0
    cve_per_package: Counter[str] = Counter()

    selected = []
    for passport in passports:
        passport_type = passport.get("passport_type")
        severity = str(passport.get("severity") or "info").lower()
        package_name = str(passport.get("component") or passport.get("software_name") or "")
        if passport_type in {"software", "software_group"} and software_count >= max_software:
            continue
        if passport_type == "software" and cve_per_package[package_name] >= max_cve_per_package:
            continue
        if passport_type == "software" and severity == "medium" and package_name in strong_packages:
            continue
        if passport_type == "software" and severity == "low" and not include_low:
            continue
        if passport_type == "software" and severity == "info" and not include_info:
            continue
        if severity == "low" and not include_low and passport.get("passport_id") not in top_refs:
            continue
        if severity == "info" and not include_info and passport.get("passport_id") not in top_refs:
            continue
        if passport.get("passport_id") in top_refs or severity in {"critical", "high"} or PRIORITY_ORDER.get(str(passport.get("priority", "P4")).upper(), 0) >= threshold:
            selected.append(passport)
            if passport_type in {"software", "software_group"}:
                software_count += 1
            if passport_type == "software":
                cve_per_package[package_name] += 1
        if len(selected) >= max_items and software_count >= max_software:
            break
    return selected


def build_exceptions_summary(exceptions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    buckets: dict[tuple[str, str], dict[str, Any]] = {}
    for finding in exceptions:
        applicability = finding.get("applicability", {}) if isinstance(finding.get("applicability"), dict) else {}
        reason = str(applicability.get("reason") or NO_SOURCE)
        subsystem = str(finding.get("subsystem") or finding.get("type") or "unknown")
        key = (reason, subsystem)
        bucket = buckets.setdefault(
            key,
            {
                "reason": reason,
                "count": 0,
                "affected_subsystem": subsystem,
                "affected_components": set(),
                "comment": str(applicability.get("notes") or ""),
                "finding_refs": [],
            },
        )
        bucket["count"] += 1
        bucket["affected_components"].add(finding.get("title") or finding.get("finding_uid"))
        if finding.get("finding_uid"):
            bucket["finding_refs"].append(finding["finding_uid"])
    result = []
    for bucket in buckets.values():
        result.append({**bucket, "affected_components": unique_sorted(list(bucket["affected_components"]))[:10]})
    return sorted(result, key=lambda item: (-item["count"], item["reason"]))
