from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_session_file_record(path: Path) -> dict[str, Any]:
    """Load session file (JSON or YAML). Returns a plain dict with optional keys headers, cookies, bearer_token_env."""

    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore[import-untyped]
        except ImportError as exc:
            raise RuntimeError(
                "YAML session files require PyYAML. Install with: pip install pyyaml"
            ) from exc
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)

    if not isinstance(data, dict):
        raise ValueError("session file root must be a JSON object")
    headers = data.get("headers")
    cookies = data.get("cookies")
    bearer_token_env = data.get("bearer_token_env")
    out: dict[str, Any] = {}
    if headers is not None:
        if not isinstance(headers, dict):
            raise ValueError("headers must be an object")
        out["headers"] = {str(k): str(v) for k, v in headers.items()}
    if cookies is not None:
        if not isinstance(cookies, dict):
            raise ValueError("cookies must be an object")
        out["cookies"] = {str(k): str(v) for k, v in cookies.items()}
    if bearer_token_env is not None:
        out["bearer_token_env"] = str(bearer_token_env).strip()
    return out
