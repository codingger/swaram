"""System 1: fast behavioral screen against a learned per-role baseline.

Dual-process idea: rules (System 2) reason slowly and explicitly; this screen
cheaply asks "has an agent in this role ever done this before?". Each behavior an
agent shows is scored by its surprise, -log2 P(an agent of this role shows it),
estimated from benign runs with Laplace smoothing. Only rare behaviors count.

The baseline is learned continually: new runs confirmed clean can be folded in
without forgetting earlier ones (counts only ever accumulate).
"""
from __future__ import annotations

import copy
import math
from collections import defaultdict

from app.schemas import Agent, NormalizedEvent

RARE_P = 0.1  # behaviors seen in >= 10% of same-role agents are "normal"


def behavior_key(e: NormalizedEvent) -> str:
    """Structured description of what an agent did. Free text is never used."""
    if e.event_type == "message":
        ref = e.payload.get("data_ref")
        return f"message:send{f':data_ref={ref}' if ref else ''}"
    if e.event_type == "data_transfer":
        return f"data_transfer:{e.action}:{e.resource}->{e.target}"
    if e.event_type == "resource_access":
        return f"resource_access:{e.action}:{e.resource}"
    if e.event_type == "tool_call":
        return f"tool_call:{e.resource or e.action}"
    return f"{e.event_type}:{e.action}"


def agent_behaviors(events: list[NormalizedEvent]) -> dict[str, dict[str, list[str]]]:
    """agent_id -> behavior -> event_ids exhibiting it."""
    out: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    for e in events:
        out[e.agent_id][behavior_key(e)].append(e.event_id)
    return out


def empty_profile() -> dict:
    return {"roles": {}, "runs_learned": 0}


def learn(profile: dict | None, events: list[NormalizedEvent], agents: list[Agent], run_id: str | None = None) -> dict:
    """Fold one benign run into the profile (continual learning, no forgetting)."""
    profile = copy.deepcopy(profile) if profile else empty_profile()
    if run_id:
        if run_id in profile.setdefault("learned_run_ids", []):
            raise ValueError(f"{run_id} is already part of the baseline")
        profile["learned_run_ids"].append(run_id)
    seen = agent_behaviors(events)
    for a in agents:
        role = profile["roles"].setdefault(a.role, {"agents": 0, "behaviors": {}})
        role["agents"] += 1
        for b in seen.get(a.agent_id, {}):
            role["behaviors"][b] = role["behaviors"].get(b, 0) + 1
    profile["runs_learned"] += 1
    return profile


def probability(profile: dict, role: str, behavior: str) -> float | None:
    r = profile.get("roles", {}).get(role)
    if not r or not r["agents"]:
        return None
    return (r["behaviors"].get(behavior, 0) + 1) / (r["agents"] + 2)


def score_agent(profile: dict, role: str | None, behaviors: dict[str, list[str]]) -> tuple[float, list[dict]]:
    """Total surprise in bits and the rare behaviors that produced it."""
    if not role:
        return 0.0, []
    rare = []
    for b, event_ids in sorted(behaviors.items()):
        p = probability(profile, role, b)
        if p is None or p >= RARE_P:
            continue
        rare.append({"behavior": b, "p": round(p, 4), "bits": round(-math.log2(p), 2), "event_ids": event_ids})
    return round(sum(r["bits"] for r in rare), 2), rare


def summary(profile: dict | None) -> dict:
    profile = profile or empty_profile()
    roles = profile.get("roles", {})
    return {
        "trained": bool(roles),
        "runs_learned": profile.get("runs_learned", 0),
        "learned_run_ids": profile.get("learned_run_ids", []),
        "agents_learned": sum(r["agents"] for r in roles.values()),
        "roles": {k: {"agents": v["agents"], "behaviors": len(v["behaviors"])} for k, v in sorted(roles.items())},
    }
