"""Pluggable agent-behaviour adapters.

Adapters only write the free-text `content` of agent messages. They never decide
which actions an agent takes and detection never trusts their text as evidence.
"""
from __future__ import annotations

import os

from app.adapters.base import AgentAdapter, DeterministicAdapter
from app.config import get_settings


def available_adapters() -> list[dict[str, object]]:
    s = get_settings()
    return [
        {"id": "deterministic", "label": "Deterministic templates", "available": True},
        {
            "id": "anthropic",
            "label": f"Anthropic API ({s.llm_model})",
            "available": bool(os.getenv("ANTHROPIC_API_KEY")),
        },
    ]


def get_adapter(name: str) -> AgentAdapter:
    if name in ("", "deterministic"):
        return DeterministicAdapter()
    if name == "anthropic":
        from app.adapters.anthropic_adapter import AnthropicAdapter

        s = get_settings()
        return AnthropicAdapter(model=s.llm_model, max_calls=s.llm_max_calls)
    raise ValueError(f"Unknown agent backend: {name}")
