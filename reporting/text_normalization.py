from __future__ import annotations

import re
from typing import Any


CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


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


def fix_missing_spaces_after_punctuation(value: Any) -> str:
    text = normalize_whitespace(value)
    text = re.sub(r"([.!?;:])(?=[А-ЯA-ZЁ])", r"\1 ", text)
    text = re.sub(r"([а-яa-zё])(?=[А-ЯЁ][а-яё])", r"\1 ", text)
    return text


def limit_summary_text(value: Any, length: int = 700) -> str:
    text = fix_missing_spaces_after_punctuation(value)
    if len(text) <= length:
        return text
    shortened = text[: max(0, length - 1)].rsplit(" ", 1)[0].rstrip(".,;: ")
    return f"{shortened}."
