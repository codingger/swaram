"""Human review queue for live containment (Security Response).

Every time the live guard pauses an agent, holds its outbound transfers or quarantines an untrusted input, a review
item is created. A person then decides:

- **release**: the agent may continue. If the run is still live, the guard un-pauses it (or lifts the egress hold)
  right away and won't re-pause or re-hold it for risk alone. What still applies: the hijack tripwire (an out-of-policy
  action right after untrusted input) and the static gateway in `enforce` mode. A release is a human's call.
  A quarantined input can't be re-delivered; releasing it records that the sender was verified.
- **confirm**: the containment was right; the agent stays contained and is recorded as a confirmed culprit.

Items live in the `reviews` collection and every change is pushed on the live stream as a `review` message.
"""
from __future__ import annotations

from typing import Any

from app.services.live_hub import active_guard, get_hub
from app.timeutil import now_iso

KINDS = {"agent": "paused_agent", "egress": "held_egress"}


def review_id(run_id: str, agent_id: str, kind: str) -> str:
    return f"rev-{run_id.removeprefix('run-')}-{agent_id}-{kind}"


def record(store, run_id: str, kind: str, data: dict) -> dict:
    """Create (or keep) the review item for one containment / quarantine."""
    rid = review_id(run_id, data["agent_id"], kind)
    existing = store.get("reviews", rid)
    if existing:
        return existing
    item = {"review_id": rid, "run_id": run_id, "kind": kind, "agent_id": data["agent_id"], "role": data.get("role"),
            "trigger": data.get("trigger"), "explanation": data.get("explanation") or data.get("reason"),
            "resource": data.get("resource"), "claimed_sender": data.get("claimed_sender"),
            "risk": data.get("risk"), "status": "pending", "created_at": now_iso(), "decided_at": None, "note": None,
            "effect": None}
    store.put("reviews", rid, item)
    get_hub().publish("review", {"action": "created", "item": item}, run_id)
    return item


def recorder(store, run_id: str):
    """Callback for LiveStream: turns each containment / quarantine into a pending review item."""
    def on(kind: str, data: dict[str, Any]) -> None:
        record(store, run_id, "quarantined_input" if kind == "quarantine" else KINDS.get(data.get("scope"), "paused_agent"),
               data)
    return on


def items(store, status: str | None = None, run_id: str | None = None) -> list[dict]:
    docs = store.list("reviews", run_id=run_id) if run_id else store.list("reviews")
    return sorted((d for d in docs if status in (None, d.get("status"))), key=lambda d: d["created_at"], reverse=True)


def decide(store, rid: str, decision: str, note: str | None = None) -> dict:
    if decision not in ("release", "confirm"):
        raise ValueError("decision must be 'release' or 'confirm'")
    item = store.get("reviews", rid)
    if item is None:
        raise ValueError(f"no review item {rid}")
    if item["status"] != "pending":
        raise ValueError(f"{rid} was already decided ({item['status']})")
    guard = active_guard(item["run_id"])
    if decision == "confirm":
        effect = "kept contained"
    elif item["kind"] == "quarantined_input":
        effect = "sender marked as verified (the input itself is not re-delivered)"
    elif guard is None:
        effect = "recorded; the run has already finished, so nothing was running to release"
    else:
        effect = guard.release(item["agent_id"], egress_only=item["kind"] == "held_egress")
    item.update(status="released" if decision == "release" else "confirmed", decided_at=now_iso(), note=note, effect=effect)
    store.put("reviews", rid, item)
    get_hub().publish("review", {"action": "decided", "item": item}, item["run_id"])
    return item
