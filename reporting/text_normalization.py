from __future__ import annotations

import re
from typing import Any


CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
REGISTRY_DESCRIPTION_NOTE = "Полное описание доступно в passport_registry.html."


def remove_control_chars(value: Any) -> str:
    return CONTROL_CHARS_RE.sub("", str(value or ""))


def collapse_repeated_newlines(value: Any) -> str:
    return re.sub(r"\n{3,}", "\n\n", str(value or ""))


def normalize_whitespace(value: Any) -> str:
    text = remove_control_chars(value)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[ \t\f\v]+", " ", text)
    text = re.sub(r" *\n *", "\n", text)
    return collapse_repeated_newlines(text).strip()


def fix_joined_sentences(value: Any) -> str:
    text = normalize_whitespace(value)
    text = re.sub(r"([.!?])(?=[A-ZА-ЯЁ])", r"\1 ", text)
    text = re.sub(r"(\))(?=[A-ZА-ЯЁ])", r"\1. ", text)
    return text


def fix_missing_spaces(value: Any) -> str:
    text = fix_joined_sentences(value)
    replacements = {
        "resolved:net": "resolved: net",
        "sock()Syzkaller": "sock(). Syzkaller",
        "closedconcurrently": "closed concurrently",
        "justfreed": "just freed",
        "using anipc_msg": "using an ipc_msg",
        "traditionalnetwork": "traditional network",
        "inferopenvpn": "infer OpenVPN",
    }
    for old, new in replacements.items():
        text = re.sub(re.escape(old), new, text, flags=re.I)
    text = re.sub(r"([a-zA-Z0-9])(\([^)]{1,40}\))(?=[A-Za-zА-Яа-яЁё])", r"\1 \2 ", text)
    text = re.sub(r"(\([^)]{1,40}\))(?=[A-Za-zА-Яа-яЁё])", r"\1 ", text)
    text = re.sub(r"([.!?;:])(?=[A-Za-zА-Яа-яЁё])", r"\1 ", text)
    text = re.sub(r"\s{2,}", " ", text)
    return text.strip()


def fix_missing_spaces_after_punctuation(value: Any) -> str:
    text = fix_missing_spaces(value)
    text = re.sub(r"([.!?;:])(?=[А-ЯA-ZЁ])", r"\1 ", text)
    text = re.sub(r"([а-яa-zё])(?=[А-ЯЁ][а-яё])", r"\1 ", text)
    return text


def truncate_at_sentence_boundary(value: Any, max_chars: int) -> str:
    text = fix_missing_spaces(value)
    if len(text) <= max_chars:
        return text
    candidate = text[:max_chars].rstrip()
    match = list(re.finditer(r"[.!?](?:\s|$)", candidate))
    if match and match[-1].end() >= max_chars * 0.45:
        return candidate[: match[-1].end()].strip()
    return candidate.rsplit(" ", 1)[0].rstrip(".,;: ") + "."


def limit_summary_text(value: Any, length: int = 700) -> str:
    text = fix_missing_spaces_after_punctuation(value)
    if len(text) <= length:
        return text
    return truncate_at_sentence_boundary(text, length)


def cve_impact_human(value: Any) -> str:
    text = fix_missing_spaces(value).lower()
    if re.search(r"remote code execution|\brce\b|execute arbitrary code|code execution", text):
        return "возможно выполнение непредусмотренного кода при наличии условий эксплуатации"
    if re.search(r"privilege escalation|escalat(?:e|ion)|gain privileges|elevat(?:e|ion)", text):
        return "возможно повышение привилегий при наличии условий эксплуатации"
    if re.search(r"information disclosure|sensitive information|leak|confidentiality", text):
        return "возможна утечка сведений или нарушение конфиденциальности данных"
    if re.search(r"use-after-free|use after free|memory corruption|heap overflow|buffer overflow|out-of-bounds|out of bounds", text):
        return "возможен сбой компонента, отказ в обслуживании или выполнение непредусмотренных операций при эксплуатации ошибки памяти"
    if re.search(r"null pointer|null dereference|null-ptr|denial of service|\bdos\b|crash|panic", text):
        return "возможен отказ в обслуживании или аварийное завершение компонента"
    return "возможна эксплуатация уязвимости установленного программного компонента; конкретные последствия требуют уточнения по данным внешнего источника"


def build_cve_description_human(finding: dict[str, Any], max_chars: int = 700) -> str:
    raw = fix_missing_spaces(finding.get("description"))
    package = finding.get("package", {}) if isinstance(finding.get("package"), dict) else {}
    package_name = str(package.get("name") or "установленном программном компоненте")
    cve = str(finding.get("cve") or "CVE")
    lower = raw.lower()
    impact = cve_impact_human(raw)
    is_kernel = package_name.startswith(("linux-image", "linux-modules", "linux-headers")) or "linux kernel" in lower or "kernel" in lower
    has_memory_signal = bool(re.search(r"use-after-free|use after free|memory corruption|null pointer|null dereference|out-of-bounds|out of bounds", lower))

    if not raw or raw.lower() in {"not provided", "unknown"}:
        base = (
            "Описание не сформировано автоматически; полные исходные сведения доступны в паспортном реестре. "
            "По данным источника уязвимость относится к установленному программному компоненту и требует обновления пакета."
        )
    elif is_kernel and has_memory_signal:
        base = (
            "В ядре Linux выявлена ошибка обработки установленного компонента, связанная с некорректной работой с памятью "
            "или аварийным завершением при определенных условиях эксплуатации. "
            f"{impact.capitalize()}."
        )
    else:
        base = (
            f"В установленном пакете {package_name} выявлена уязвимость {cve}, затрагивающая установленную версию компонента. "
            f"{impact.capitalize()}."
        )

    text = truncate_at_sentence_boundary(base, max_chars)
    if REGISTRY_DESCRIPTION_NOTE not in text:
        text = f"{text.rstrip()} {REGISTRY_DESCRIPTION_NOTE}"
    return text
