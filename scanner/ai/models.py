from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

FollowupModule = Literal["http_probe", "dir_enum", "port_scan"]


class AiBaseModel(BaseModel):
    model_config = ConfigDict(extra="ignore")


class TargetRisk(AiBaseModel):
    """An LLM (or heuristic) risk assessment for a single observed host/subdomain/URL."""

    target: str
    risk_score: float = Field(ge=0.0, le=1.0)
    rationale: str = ""
    signals: list[str] = Field(default_factory=list)
    # Deeper scans the analyst suggests for this target (advisory; the planner
    # decides what is actually safe and in-scope to enqueue).
    suggested_modules: list[FollowupModule] = Field(default_factory=list)


class TriageResult(AiBaseModel):
    """Structured output of one ai_triage pass over accumulated findings."""

    summary: str = ""
    targets: list[TargetRisk] = Field(default_factory=list)
    # "llm" when produced by a model, "heuristic" when produced by the offline fallback.
    source: Literal["llm", "heuristic"] = "heuristic"
    model: str = ""


class FollowupAction(AiBaseModel):
    """A concrete, scope-checked scan the planner decided to enqueue."""

    module: FollowupModule
    scope: str
    risk_score: float = Field(ge=0.0, le=1.0)
    reason: str = ""
