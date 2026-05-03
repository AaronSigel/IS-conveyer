from typing import Any

from reporting.filters import apply_filters, normalize_finding, normalize_findings

PRESETS = {
    "all_vulnerability": (
        "All vulnerability",
        {"finding_type": {"op": "eq", "value": "software_vulnerability"}},
    ),
    "fail_vulnerability": (
        "Fail vulnerability",
        {
            "finding_type": {"op": "eq", "value": "software_vulnerability"},
            "status": {"op": "in", "value": ["fail"]},
        },
    ),
}


def filters_from_form(form: dict[str, Any]) -> dict[str, Any]:
    preset = form.get("preset")
    if preset and preset in PRESETS:
        return dict(PRESETS[preset][1])
    return dict(PRESETS["all_vulnerability"][1])
