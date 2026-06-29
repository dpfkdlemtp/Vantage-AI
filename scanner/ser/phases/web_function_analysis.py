from __future__ import annotations

from scanner.ser.models import AuthSession


def analyze_functions_stub(session: AuthSession) -> dict[str, object]:
    """
    WEB_FUNCTION_ANALYSIS placeholder: maps discovered behaviors to controlled validations.
    Uses only redacted session metadata in outputs.
    """

    return {
        "phase": "WEB_FUNCTION_ANALYSIS",
        "audit": session.model_for_audit(),
        "note": "Wire function-to-validation mapping to controlled_validation with approval gates.",
    }
