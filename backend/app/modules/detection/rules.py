"""Rule-based threat detection over normalized events.

Rules only use structured event fields (agent, action, resource, target, status,
data_ref). Free-text message content - which may be LLM-written - is never evidence.
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field

from app.modules.simulator.world import EXTERNAL_ALLOWLIST, EXTERNAL_PREFIX, RESTRICTED_RESOURCES, ROLE_PERMISSIONS
from app.schemas import Agent, Alert, DetectionRule, EvidenceRef, NormalizedEvent
from app.timeutil import now_iso, parse_iso

READ_ACTIONS = {"read", "copy", "download", "export", "query"}

DEFAULT_RULES: list[DetectionRule] = [
    DetectionRule(
        rule_id="SG-001",
        name="Unauthorized resource access",
        description="An agent touched a restricted resource that its role is not permitted to use (attempted or completed).",
        severity="high",
        recommended_action="block",
        params={"restricted_resources": RESTRICTED_RESOURCES},
    ),
    DetectionRule(
        rule_id="SG-002",
        name="External data transfer",
        description="Data sent to an external destination that is not on the allowlist. Critical-path when the data is restricted.",
        severity="high",
        recommended_action="block",
        params={"external_prefix": EXTERNAL_PREFIX, "allowlist": EXTERNAL_ALLOWLIST, "restricted_resources": RESTRICTED_RESOURCES},
    ),
    DetectionRule(
        rule_id="SG-003",
        name="Coordinated leakage chain",
        description="Restricted data read by one agent, handed to other agents via messages carrying a data_ref, "
        "then sent externally by a different agent within the correlation window.",
        severity="critical",
        recommended_action="pause",
        params={"window_seconds": 600, "restricted_resources": RESTRICTED_RESOURCES, "allowlist": EXTERNAL_ALLOWLIST},
    ),
]


def alert_id(run_id: str, rule_id: str, event_ids: list[str]) -> str:
    digest = hashlib.sha1(f"{run_id}|{rule_id}|{','.join(sorted(event_ids))}".encode()).hexdigest()[:10]
    return f"alt-{digest}"


def _make_alert(rule: DetectionRule, run_id: str, agent_ids: list[str], events: list[NormalizedEvent], resource: str | None,
                reason: str, severity: str | None = None) -> Alert:
    event_ids = [e.event_id for e in events]
    return Alert(
        alert_id=alert_id(run_id, rule.rule_id, event_ids),
        run_id=run_id,
        rule_id=rule.rule_id,
        rule_name=rule.name,
        severity=severity or rule.severity,
        agent_ids=agent_ids,
        event_ids=event_ids,
        resource=resource,
        reason=reason,
        recommended_action=rule.recommended_action,
        evidence=[EvidenceRef(event_id=e.event_id, timestamp=e.timestamp, summary=e.summary) for e in events],
        created_at=now_iso(),
    )


def _permissions(agent_id: str, role: str | None, registry: dict[str, Agent]) -> set[str] | None:
    if agent_id in registry:
        return set(registry[agent_id].permissions)
    if role in ROLE_PERMISSIONS:
        return set(ROLE_PERMISSIONS[role])
    return None  # unknown agent: nothing is permitted


def rule_unauthorized_access(rule: DetectionRule, run_id: str, events: list[NormalizedEvent], registry: dict[str, Agent]) -> list[Alert]:
    restricted = set(rule.params.get("restricted_resources", []))
    hits: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for e in events:
        if e.event_type != "resource_access" or e.resource not in restricted:
            continue
        perms = _permissions(e.agent_id, e.agent_role, registry) or set()
        if e.resource not in perms:
            hits[e.agent_id].append(e)
    alerts = []
    for agent_id, evs in hits.items():
        resources = sorted({e.resource for e in evs if e.resource})
        completed = sum(1 for e in evs if e.status == "success")
        denied = sum(1 for e in evs if e.status == "denied")
        reason = (f"{agent_id} attempted {len(evs)} access(es) to restricted resource(s) {', '.join(resources)} outside its role "
                  f"permissions ({completed} completed, {denied} denied by gateway).")
        alerts.append(_make_alert(rule, run_id, [agent_id], evs, ",".join(resources), reason,
                                  severity="critical" if completed and len(evs) >= 3 else rule.severity))
    return alerts


def rule_external_transfer(rule: DetectionRule, run_id: str, events: list[NormalizedEvent], registry: dict[str, Agent]) -> list[Alert]:
    prefix = rule.params.get("external_prefix", EXTERNAL_PREFIX)
    allow = set(rule.params.get("allowlist", []))
    restricted = set(rule.params.get("restricted_resources", []))
    alerts = []
    for e in events:
        if e.event_type != "data_transfer" or not (e.target or "").startswith(prefix) or e.target in allow:
            continue
        sensitive = e.resource in restricted
        reason = (f"{e.agent_id} {e.action} {e.resource or 'data'} to non-allowlisted destination {e.target} "
                  f"(status {e.status}{', restricted data' if sensitive else ''}).")
        alerts.append(_make_alert(rule, run_id, [e.agent_id], [e], e.resource, reason, severity="high" if sensitive else "medium"))
    return alerts


@dataclass
class _Taint:
    resource: str
    chain: list[str]
    events: list[NormalizedEvent] = field(default_factory=list)


def rule_coordinated_leakage(rule: DetectionRule, run_id: str, events: list[NormalizedEvent], registry: dict[str, Agent]) -> list[Alert]:
    window = float(rule.params.get("window_seconds", 600))
    restricted = set(rule.params.get("restricted_resources", []))
    allow = set(rule.params.get("allowlist", []))
    taint: dict[str, _Taint] = {}
    alerts = []

    def within(t: _Taint, e: NormalizedEvent) -> bool:
        if not t.events:
            return True
        return (parse_iso(e.timestamp) - parse_iso(t.events[0].timestamp)).total_seconds() <= window

    for e in events:
        if e.status != "success" and e.event_type != "data_transfer":
            continue
        if e.event_type == "resource_access" and e.resource in restricted and e.action in READ_ACTIONS:
            taint[e.agent_id] = _Taint(resource=e.resource, chain=[e.agent_id], events=[e])
        elif e.event_type == "message" and e.target and e.payload.get("data_ref") in restricted:
            ref = e.payload["data_ref"]
            src = taint.get(e.agent_id)
            if src is None or src.resource != ref or not within(src, e):
                # Sender evidently holds the data even if its read event is missing.
                src = _Taint(resource=ref, chain=[e.agent_id], events=[])
            if e.target not in src.chain:
                taint[e.target] = _Taint(resource=ref, chain=src.chain + [e.target], events=src.events + [e])
        elif e.event_type == "data_transfer" and (e.target or "").startswith(EXTERNAL_PREFIX) and e.target not in allow:
            t = taint.get(e.agent_id)
            if t and len(t.chain) >= 2 and within(t, e):
                evs = t.events + [e]
                reason = (f"Restricted data {t.resource} moved along {' -> '.join(t.chain)} and was sent to {e.target} "
                          f"by {e.agent_id} (transfer status {e.status}).")
                alerts.append(_make_alert(rule, run_id, list(t.chain), evs, t.resource, reason))
    return alerts


RULE_IMPLS = {
    "SG-001": rule_unauthorized_access,
    "SG-002": rule_external_transfer,
    "SG-003": rule_coordinated_leakage,
}


def run_rules(run_id: str, events: list[NormalizedEvent], agents: list[Agent], rules: list[DetectionRule] | None = None) -> list[Alert]:
    registry = {a.agent_id: a for a in agents}
    ordered = sorted(events, key=lambda e: (e.timestamp, e.sequence))
    alerts: list[Alert] = []
    for rule in rules or DEFAULT_RULES:
        impl = RULE_IMPLS.get(rule.rule_id)
        if rule.enabled and impl:
            alerts.extend(impl(rule, run_id, ordered, registry))
    return alerts
