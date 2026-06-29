"""Provider-agnostic LLM client used by the ai_triage analyst.

Calls are made over the shared ``httpx`` dependency (no extra SDK). The client is
intentionally small and best-effort: any failure raises :class:`LLMUnavailable`,
which callers catch to fall back to the deterministic heuristic. No secrets are
logged and the API key is read from the environment by name only.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

import httpx

from scanner.models import AiProvider

_ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
_ANTHROPIC_VERSION = "2023-06-01"
_OPENAI_URL = "https://api.openai.com/v1/chat/completions"

_DEFAULT_MODELS: dict[AiProvider, str] = {
    "anthropic": "claude-sonnet-4-6",
    "openai": "gpt-4o-mini",
}

_JSON_BLOCK = re.compile(r"\{.*\}", re.DOTALL)


class LLMUnavailable(RuntimeError):
    """Raised when the LLM cannot be reached or returned an unusable response."""


def resolve_api_key(api_key_env: str) -> str | None:
    """Return the API key value from the named env var, or None if unset/blank."""

    value = os.environ.get(api_key_env or "")
    value = (value or "").strip()
    return value or None


def resolve_model(provider: AiProvider, model: str) -> str:
    model = (model or "").strip()
    return model or _DEFAULT_MODELS[provider]


def complete_json(
    *,
    provider: AiProvider,
    model: str,
    api_key: str,
    system: str,
    user: str,
    max_tokens: int = 2048,
    timeout_seconds: int = 60,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    """Send one prompt and return the parsed JSON object from the model response.

    ``transport`` is injectable so tests can run fully offline. Raises
    :class:`LLMUnavailable` on any transport, status, or parsing failure.
    """

    resolved_model = resolve_model(provider, model)
    if provider == "anthropic":
        url, headers, payload = _anthropic_request(resolved_model, api_key, system, user, max_tokens)
    else:
        url, headers, payload = _openai_request(resolved_model, api_key, system, user, max_tokens)

    try:
        with httpx.Client(timeout=timeout_seconds, transport=transport) as client:
            response = client.post(url, headers=headers, json=payload)
    except httpx.HTTPError as exc:  # network/timeout/connection errors
        raise LLMUnavailable(f"{provider} request failed: {exc}") from exc

    if response.status_code != 200:
        raise LLMUnavailable(f"{provider} returned HTTP {response.status_code}")

    try:
        body = response.json()
        text = _extract_text(provider, body)
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        raise LLMUnavailable(f"{provider} response was not understood: {exc}") from exc

    return _parse_json_object(text)


def _anthropic_request(
    model: str, api_key: str, system: str, user: str, max_tokens: int
) -> tuple[str, dict[str, str], dict[str, Any]]:
    headers = {
        "x-api-key": api_key,
        "anthropic-version": _ANTHROPIC_VERSION,
        "content-type": "application/json",
    }
    payload: dict[str, Any] = {
        "model": model,
        "max_tokens": max_tokens,
        "system": system,
        "messages": [{"role": "user", "content": user}],
    }
    return _ANTHROPIC_URL, headers, payload


def _openai_request(
    model: str, api_key: str, system: str, user: str, max_tokens: int
) -> tuple[str, dict[str, str], dict[str, Any]]:
    headers = {
        "Authorization": f"Bearer {api_key}",
        "content-type": "application/json",
    }
    payload: dict[str, Any] = {
        "model": model,
        "max_tokens": max_tokens,
        "temperature": 0,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    return _OPENAI_URL, headers, payload


def _extract_text(provider: AiProvider, body: dict[str, Any]) -> str:
    if provider == "anthropic":
        blocks = body["content"]
        return "".join(str(block.get("text", "")) for block in blocks if isinstance(block, dict))
    return str(body["choices"][0]["message"]["content"])


def _parse_json_object(text: str) -> dict[str, Any]:
    text = (text or "").strip()
    if not text:
        raise LLMUnavailable("empty model response")
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        match = _JSON_BLOCK.search(text)
        if not match:
            raise LLMUnavailable("model response contained no JSON object")
        try:
            parsed = json.loads(match.group(0))
        except json.JSONDecodeError as exc:
            raise LLMUnavailable(f"model JSON was invalid: {exc}") from exc
    if not isinstance(parsed, dict):
        raise LLMUnavailable("model JSON was not an object")
    return parsed
