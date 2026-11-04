"""Pluggable agent-behaviour adapters.

Adapters write free-text content and generate agent reasoning responses.
They never bypass policy checks, and detection never trusts their text as evidence.
"""
from __future__ import annotations

import os

from app.adapters.base import AgentAdapter, DeterministicAdapter
from app.config import get_settings


def available_adapters() -> list[dict[str, object]]:
    s = get_settings()
    gemini_key = os.getenv("GEMINI_API_KEY")
    gemini_model = os.getenv("GEMINI_MODEL") or s.gemini_model
    return [
        {"id": "deterministic", "label": "Deterministic templates", "available": True},
        {
            "id": "gemini",
            "label": f"Google Gemini API ({gemini_model})",
            "available": bool(gemini_key),
        },
        {
            "id": "anthropic",
            "label": f"Anthropic API ({s.llm_model})",
            "available": bool(os.getenv("ANTHROPIC_API_KEY")),
        },
    ]


def get_adapter(name: str) -> AgentAdapter:
    if name in ("", "deterministic"):
        return DeterministicAdapter()
    if name == "gemini":
        from app.adapters.gemini_adapter import GeminiAdapter

        s = get_settings()
        return GeminiAdapter(
            model=os.getenv("GEMINI_MODEL") or s.gemini_model,
            max_calls=s.llm_max_calls,
        )
    if name == "anthropic":
        from app.adapters.anthropic_adapter import AnthropicAdapter

        s = get_settings()
        return AnthropicAdapter(model=s.llm_model, max_calls=s.llm_max_calls)
    raise ValueError(f"Unknown agent backend: {name}")


__all__ = [
    "AgentAdapter",
    "DeterministicAdapter",
    "available_adapters",
    "get_adapter",
]


__all__ = ["AgentAdapter", "DeterministicAdapter", "available_adapters", "get_adapter"]
