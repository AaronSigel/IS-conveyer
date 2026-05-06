from typing import Any


STATUS_LABELS = {
    "pending": "ожидает запуска",
    "running": "выполняется",
    "succeeded": "завершено успешно",
    "success": "завершено успешно",
    "completed": "завершено",
    "failed": "завершено с ошибкой",
    "fail": "ошибка",
    "pass": "успешно",
    "passed": "успешно",
    "timeout": "тайм-аут",
    "cancelled": "отменено",
    "not_applicable": "не применимо",
    "unknown": "неизвестно",
}

SEVERITY_LABELS = {
    "critical": "критическая",
    "high": "высокая",
    "medium": "средняя",
    "low": "низкая",
    "info": "информационная",
    "unknown": "неизвестно",
}

MODE_LABELS = {
    "combined": "общий",
    "split": "раздельный",
    "summary": "краткий",
}


def _normalize(value: Any) -> str:
    return str(value or "unknown").strip().lower()


def ru_status(value: Any) -> str:
    return STATUS_LABELS.get(_normalize(value), str(value or "неизвестно"))


def ru_severity(value: Any) -> str:
    return SEVERITY_LABELS.get(_normalize(value), str(value or "неизвестно"))


def ru_mode(value: Any) -> str:
    return MODE_LABELS.get(_normalize(value), str(value or "не задан"))


def install_jinja_filters(env: Any) -> None:
    env.filters["ru_status"] = ru_status
    env.filters["ru_severity"] = ru_severity
    env.filters["ru_mode"] = ru_mode
