from __future__ import annotations

from scanner.note_suggestions import generate_note_suggestion


def test_generate_note_suggestion_returns_non_empty() -> None:
    text = generate_note_suggestion({"port": 9999, "name": "unknown", "protocol": "tcp"})
    assert isinstance(text, str)
    assert text.strip()


def test_generate_note_suggestion_http_contains_admin() -> None:
    text = generate_note_suggestion({"port": 443, "name": "https", "protocol": "tcp"})
    assert "admin" in text.lower()


def test_generate_note_suggestion_ssh_contains_ssh() -> None:
    text = generate_note_suggestion({"port": 22, "name": "ssh", "protocol": "tcp"})
    assert "ssh" in text.lower()
