from __future__ import annotations

import logging


def get_logger(name: str) -> logging.Logger:
    """Module logger accessor.

    Centralised so handler configuration / formatting can be tightened in one
    place later without touching every call site.
    """

    return logging.getLogger(name)
