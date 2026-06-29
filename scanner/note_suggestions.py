from __future__ import annotations

from typing import Any


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def generate_note_suggestion(service: dict[str, Any]) -> str:
    port = _as_int(service.get("port"))
    name = str(service.get("name") or service.get("service_name") or "").strip().lower()
    protocol = str(service.get("protocol") or "tcp").strip().lower()
    suggestions: list[str] = []

    is_http_like = name in {"http", "https"} or (port in {80, 443, 8080, 8443})
    if is_http_like:
        suggestions.append("HTTPS/HTTP service detected")
        suggestions.append("Possible web admin panel exposure")
        suggestions.append("Consider directory scan with ffuf")

    is_ssh_like = name == "ssh" or port == 22
    if is_ssh_like:
        suggestions.append("SSH exposed - review auth policy and hardening")
        suggestions.append("Check weak credentials and remote access controls")

    db_ports = {1433, 1521, 3306, 5432, 6379, 27017}
    if port in db_ports or "mysql" in name or "postgres" in name or "mongo" in name:
        suggestions.append("Database service exposure detected")
        suggestions.append("Verify network ACL and trusted source restrictions")

    if not suggestions:
        suggestions.append(f"{protocol.upper()} service discovered")
        suggestions.append("Review necessity and access policy for this port")

    return "\n".join(suggestions)
