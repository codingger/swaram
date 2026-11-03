"""Deterministic multi-agent simulator.

Same (scenario, agent_count, seed, base_time) -> same events, apart from the run id
that prefixes every agent/event id.
"""
from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta

from app.adapters import get_adapter
from app.adapters.base import AgentAdapter
from app.modules.simulator.gateway import PolicyGateway
from app.modules.simulator.world import (
    ROLE_ORDER,
    ROLE_OUTPUT,
    ROLE_PERMISSIONS,
    ROLE_TOOLS,
    SCENARIOS_BY_ID,
    TOPICS,
)
from app.schemas import Agent, RawEvent, Run, RunLabels, ScenarioConfig, SimulationResult
from app.timeutil import iso, now_iso, utcnow

ROUNDS = 2


class AgentRunner:
    """Executes agent actions, routing protected ones through the gateway first."""

    def __init__(self, run_id: str, run_hex: str, base_time: datetime, rng: random.Random, gateway: PolicyGateway, adapter: AgentAdapter):
        self.run_id = run_id
        self.run_hex = run_hex
        self.clock = base_time
        self.rng = rng
        self.gateway = gateway
        self.adapter = adapter
        self.events: list[RawEvent] = []
        self.malicious_event_ids: list[str] = []

    def emit(self, agent: Agent, event_type: str, action: str, *, status: str = "success", target: str | None = None,
             resource: str | None = None, gateway_decision: str | None = None, payload: dict | None = None,
             malicious: bool = False) -> RawEvent:
        self.clock += timedelta(milliseconds=self.rng.randint(400, 2500))
        seq = len(self.events) + 1
        event = RawEvent(
            run_id=self.run_id,
            event_id=f"evt-{self.run_hex}-{seq:04d}",
            agent_id=agent.agent_id,
            timestamp=iso(self.clock),
            event_type=event_type,
            action=action,
            status=status,
            target=target,
            resource=resource,
            sequence=seq,
            gateway_decision=gateway_decision,
            payload=payload or {},
        )
        self.events.append(event)
        if malicious:
            self.malicious_event_ids.append(event.event_id)
        return event

    def protected(self, agent: Agent, event_type: str, action: str, *, resource: str | None = None,
                  target: str | None = None, payload: dict | None = None, malicious: bool = False) -> bool:
        """Check policy BEFORE executing. Returns True if the tool actually ran."""
        check = self.gateway.check(agent, resource=resource, target=target)
        payload = dict(payload or {})
        if check.decision != "not_checked":
            payload["gateway_reason"] = check.reason
        self.emit(agent, event_type, action, status="denied" if not check.executes else "success",
                  target=target, resource=resource, gateway_decision=check.decision, payload=payload, malicious=malicious)
        return check.executes

    def access(self, agent: Agent, resource: str, action: str = "read", malicious: bool = False) -> bool:
        return self.protected(agent, "resource_access", action, resource=resource, malicious=malicious)

    def message(self, sender: Agent, recipient: Agent, intent: str, topic: str, *, data_ref: str | None = None,
                malicious: bool = False) -> None:
        payload = {"intent": intent, "topic": topic,
                   "content": self.adapter.compose_message(sender.role, recipient.role, intent, topic)}
        if data_ref:
            payload["data_ref"] = data_ref
        self.emit(sender, "message", "send", target=recipient.agent_id, payload=payload, malicious=malicious)


def _make_agents(run_id: str, run_hex: str, count: int) -> list[Agent]:
    agents = []
    for i in range(count):
        role = ROLE_ORDER[i % len(ROLE_ORDER)]
        agents.append(Agent(
            agent_id=f"agt-{run_hex}-{i + 1:02d}",
            run_id=run_id,
            name=f"{role.title()} {i // len(ROLE_ORDER) + 1}",
            role=role,
            permissions=list(ROLE_PERMISSIONS[role]),
        ))
    return agents


def _first(agents: list[Agent], role: str) -> Agent | None:
    return next((a for a in agents if a.role == role), None)


def _normal_round(r: AgentRunner, agents: list[Agent], round_no: int) -> None:
    planner, workers = agents[0], agents[1:]
    for w in workers:
        r.message(planner, w, "assign_task", r.rng.choice(TOPICS))
    for w in workers:
        topic = r.rng.choice(TOPICS)
        r.emit(w, "task", "start", payload={"round": round_no, "topic": topic})
        if w.role == "analyst" and round_no == 1:
            source = "data/customer_pii"  # legitimate, permitted PII access
        else:
            source = r.rng.choice(w.permissions)
        r.access(w, source, "read")
        r.emit(w, "tool_call", "run", resource=ROLE_TOOLS[w.role])
        r.access(w, ROLE_OUTPUT[w.role], "write")
        if w.role == "researcher" and round_no == 1:
            r.protected(w, "data_transfer", "upload", resource="data/public", target="external:approved-partner-api")
        if len(workers) > 1 and r.rng.random() < 0.3:
            peer = r.rng.choice([x for x in workers if x is not w])
            r.message(w, peer, "share_notes", topic)
        r.message(w, planner, "report", topic)
        r.emit(w, "task", "complete", payload={"round": round_no, "topic": topic})


def _unauthorized_access(r: AgentRunner, agents: list[Agent]) -> list[Agent]:
    attacker = _first(agents, "coder")
    if attacker is None:
        return []
    r.emit(attacker, "tool_call", "run", resource="tool/shell", payload={"command": "ls secrets/"}, malicious=True)
    r.access(attacker, "secrets/api_keys", "read", malicious=True)
    r.access(attacker, "data/customer_pii", "read", malicious=True)
    r.access(attacker, "secrets/api_keys", "read", malicious=True)
    return [attacker]


def _coordinated_leakage(r: AgentRunner, agents: list[Agent]) -> list[Agent]:
    insider, exfil = _first(agents, "analyst"), _first(agents, "coder")
    if insider is None or exfil is None:
        return []
    relay = _first(agents, "researcher") if len(agents) >= 10 else None
    chain = [insider] + ([relay] if relay else []) + [exfil]
    r.access(insider, "data/customer_pii", "read", malicious=True)
    for sender, recipient in zip(chain, chain[1:]):
        r.message(sender, recipient, "handoff", "customer-extract", data_ref="data/customer_pii", malicious=True)
    r.emit(exfil, "tool_call", "run", resource="tool/compress", payload={"file": "extract.zip"}, malicious=True)
    r.protected(exfil, "data_transfer", "upload", resource="data/customer_pii", target="external:paste-site", malicious=True)
    return chain


ATTACKS = {
    "normal_collaboration": lambda r, agents: [],
    "unauthorized_access": _unauthorized_access,
    "coordinated_leakage": _coordinated_leakage,
}


def run_simulation(config: ScenarioConfig, *, run_id: str | None = None, base_time: datetime | None = None,
                   adapter: AgentAdapter | None = None) -> SimulationResult:
    if config.scenario_id not in SCENARIOS_BY_ID:
        raise ValueError(f"Unknown scenario: {config.scenario_id}")
    run_hex = run_id.removeprefix("run-") if run_id else uuid.uuid4().hex[:8]
    run_id = f"run-{run_hex}"
    base_time = base_time or utcnow().replace(microsecond=0)
    rng = random.Random(config.seed)

    agents = _make_agents(run_id, run_hex, config.agent_count)
    runner = AgentRunner(run_id, run_hex, base_time, rng, PolicyGateway(config.gateway_mode),
                         adapter or get_adapter(config.agent_backend))

    _normal_round(runner, agents, 1)
    malicious_agents = ATTACKS[config.scenario_id](runner, agents)
    _normal_round(runner, agents, 2)

    malicious_ids = {a.agent_id for a in malicious_agents}
    for a in agents:
        a.is_malicious = a.agent_id in malicious_ids

    events, dropped = runner.events, []
    if config.drop_rate > 0:
        drop_rng = random.Random(config.seed * 7919 + 1)
        kept = []
        for e in events:
            (dropped if drop_rng.random() < config.drop_rate else kept).append(e)
        events, dropped = kept, [e.event_id for e in dropped]

    run = Run(
        run_id=run_id,
        scenario_id=config.scenario_id,
        agent_count=config.agent_count,
        seed=config.seed,
        gateway_mode=config.gateway_mode,
        drop_rate=config.drop_rate,
        agent_backend=config.agent_backend,
        created_at=now_iso(),
        base_time=iso(base_time),
        stages={"simulated": now_iso()},
        counts={"agents": len(agents), "raw_events": len(events), "dropped_events": len(dropped)},
        labels=RunLabels(malicious_agent_ids=sorted(malicious_ids), malicious_event_ids=runner.malicious_event_ids),
        dropped_event_ids=dropped,
    )
    return SimulationResult(run=run, agents=agents, events=events)
