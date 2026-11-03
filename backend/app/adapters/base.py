from __future__ import annotations

from typing import Protocol

TEMPLATES = {
    "assign_task": "Please take the next {role} task for sprint item {topic}.",
    "report": "Finished {topic}; output written and ready for review.",
    "share_notes": "Sharing my notes on {topic} in case they help.",
    "handoff": "Sending over the extract for {topic} as discussed.",
}


class AgentAdapter(Protocol):
    name: str

    def compose_message(self, sender_role: str, recipient_role: str, intent: str, topic: str) -> str: ...


class DeterministicAdapter:
    name = "deterministic"

    def compose_message(self, sender_role: str, recipient_role: str, intent: str, topic: str) -> str:
        return TEMPLATES.get(intent, "{topic}").format(role=recipient_role, topic=topic)
