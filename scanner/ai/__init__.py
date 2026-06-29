"""LLM-in-the-loop triage for the ai_triage scan phase.

An analyst scores observed hosts/subdomains by risk (via an LLM when an API key is
configured, otherwise a deterministic heuristic), and a planner converts high-risk
targets into safe, in-scope follow-up scans for autonomous deeper enumeration.
"""

from scanner.ai.analyst import analyze, build_evidence, heuristic_triage
from scanner.ai.models import FollowupAction, TargetRisk, TriageResult
from scanner.ai.planner import plan_followups

__all__ = [
    "analyze",
    "build_evidence",
    "heuristic_triage",
    "plan_followups",
    "FollowupAction",
    "TargetRisk",
    "TriageResult",
]
