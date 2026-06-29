"""Translate an LLM/heuristic TriageResult into safe, in-scope follow-up scans.

The planner is the safety boundary for autonomous action. It NEVER invents new
targets: every follow-up scope must pass the caller-supplied ``in_scope`` predicate
(derived from the run's authorized target). It also enforces the risk threshold,
de-duplicates against already-queued work, and caps the total by the run budget.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from urllib.parse import urlsplit

from scanner.ai.models import FollowupAction, FollowupModule, TriageResult

# Modules the analyst is allowed to trigger autonomously. All are safe enumeration
# phases already present in the orchestrator -- no exploitation, no credential work.
ALLOWED_FOLLOWUP_MODULES: frozenset[FollowupModule] = frozenset(
    {"http_probe", "dir_enum", "port_scan"}
)


def plan_followups(
    triage: TriageResult,
    *,
    in_scope: Callable[[str], bool],
    min_risk: float,
    budget: int,
    already_scoped: Iterable[tuple[str, str]] = (),
) -> list[FollowupAction]:
    """Return de-duplicated, in-scope follow-up actions, highest risk first.

    ``already_scoped`` is the set of (module, scope) pairs already queued/run so we
    never enqueue duplicate work. ``budget`` caps how many new actions are returned.
    """

    if budget <= 0:
        return []

    seen: set[tuple[str, str]] = {(str(m), str(s)) for m, s in already_scoped}
    actions: list[FollowupAction] = []
    ranked = sorted(triage.targets, key=lambda t: t.risk_score, reverse=True)

    for target in ranked:
        if len(actions) >= budget:
            break
        if target.risk_score < min_risk:
            continue
        modules = [m for m in target.suggested_modules if m in ALLOWED_FOLLOWUP_MODULES]
        if not modules:
            modules = [_default_module_for(target.target)]
        for module in modules:
            if len(actions) >= budget:
                break
            scope = _scope_for(module, target.target)
            if not scope or not in_scope(scope):
                continue
            key = (module, scope)
            if key in seen:
                continue
            seen.add(key)
            actions.append(
                FollowupAction(
                    module=module,
                    scope=scope,
                    risk_score=target.risk_score,
                    reason=target.rationale or ", ".join(target.signals),
                )
            )
    return actions


def _default_module_for(target: str) -> FollowupModule:
    return "dir_enum" if "://" in target else "http_probe"


def _scope_for(module: FollowupModule, target: str) -> str:
    target = (target or "").strip()
    if not target:
        return ""
    if module == "dir_enum":
        return _base_url(target)
    # http_probe / port_scan operate on a bare host.
    return _hostname(target)


def _hostname(target: str) -> str:
    if "://" in target:
        host = urlsplit(target).hostname or ""
        return host.lower()
    return target.split("/", 1)[0].split(":", 1)[0].strip().lower()


def _base_url(target: str) -> str:
    if "://" in target:
        parts = urlsplit(target)
        scheme = (parts.scheme or "https").lower()
        host = parts.hostname or ""
        if not host:
            return ""
        port = f":{parts.port}" if parts.port else ""
        return f"{scheme}://{host}{port}"
    host = _hostname(target)
    return f"https://{host}" if host else ""
