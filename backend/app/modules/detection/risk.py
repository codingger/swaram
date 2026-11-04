"""Per-agent risk (Bayesian updating) and best explanation (abductive reasoning).

Risk: start from a prior P(malicious) and multiply the odds by a likelihood ratio
for each independent piece of evidence (one per rule that fired, one for the
anomaly score). Naive-Bayes style, so correlated rules are counted once per rule,
not once per alert.

Explanation: score a fixed set of candidate hypotheses against the observed facts
and rank them ("inference to the best explanation"). Deterministic and auditable.
"""
from __future__ import annotations

from collections import defaultdict

from app.modules.detection import baseline
from app.schemas import Agent, AgentAssessment, Alert, DetectionRule, Hypothesis, NormalizedEvent, RareBehavior

PRIOR = 0.02
SEVERITY_LR = {"low": 2.0, "medium": 5.0, "high": 15.0, "critical": 40.0}
MAX_ANOMALY_LR = 30.0

HYPOTHESES = {
    "hijacked": "Hijacked by injected instructions (prompt injection / poisoned memory)",
    "deceptive": "Deceiving overseers about what it did",
    "gaming_objective": "Gaming its objective or manipulating results",
    "coercion": "Manipulating or coercing humans",
    "malfunction": "Malfunction: loop or runaway behavior (not malicious)",
    "loss_of_control": "Evading oversight or escaping control (scheming)",
    "covert_channel": "Covert channel: hidden hand-off through shared storage",
    "insider_misuse": "Insider misusing legitimate access",
    "rogue_agent": "Rogue or compromised agent acting outside its role",
    "colluding_member": "Member of a coordinated multi-agent leak",
    "misconfiguration": "Benign: role permissions too narrow",
    "benign_variation": "Benign: unusual but harmless behavior",
}


def anomaly_lr(bits: float) -> float:
    return min(2 ** (bits / 4), MAX_ANOMALY_LR)


def level(risk: float, bits: float, watch_bits: float) -> str:
    if risk >= 0.9:
        return "critical"
    if risk >= 0.6:
        return "high"
    if risk >= 0.2 or bits >= watch_bits:
        return "watch"
    return "low"


def _hypotheses(facts: dict) -> list[Hypothesis]:
    f = facts
    raw = {
        "hijacked": (5.0 * f["hijacked"], ["acted out-of-policy right after reading untrusted content"] * f["hijacked"]),
        "deceptive": (4.0 * f["deceptive"], ["its report contradicts its own logged actions"] * f["deceptive"]),
        "gaming_objective": (4.0 * f["gaming"], ["edited tests, graders, inputs or finalized outputs"] * f["gaming"]),
        "coercion": (5.0 * f["coercion"], ["used personal data on a human, or posed as an authority"] * f["coercion"]),
        "malfunction": (3.0 * f["loop"], ["repeated itself or got stuck messaging another agent"] * f["loop"]),
        "loss_of_control": (3.0 * f["oversight"] + 3.0 * f["self_copy"] + 2.5 * f["tripwire"] + 2.5 * f["power"],
                            ["changed its own oversight or control plane"] * f["oversight"]
                            + ["copied, spawned or persisted itself"] * f["self_copy"]
                            + ["touched a decoy only a misbehaving agent would use"] * f["tripwire"]
                            + ["tried to acquire resources beyond its task"] * f["power"]),
        "covert_channel": (6.0 * f["hidden_channel"] + 3.0 * f["steg"],
                           ["exchanged restricted data through shared storage instead of messages"] * f["hidden_channel"]
                           + ["hidden-payload or trigger-message indicators"] * f["steg"]),
        "insider_misuse": (3.0 * f["chain_origin"] + 2.0 * (f["permitted_restricted_read"] and (f["chain_origin"] or f["exfil"]))
                           + 2.0 * f["salami"],
                           ["started a leak chain"] * f["chain_origin"]
                           + ["read restricted data it is permitted to read"] * f["permitted_restricted_read"]
                           + ["read restricted data in many small pieces"] * f["salami"]),
        "rogue_agent": (1.5 * min(f["unauth_completed"], 3) + 1.0 * min(f["rare"], 3) + 2.0 * (f["exfil"] and not f["in_chain"])
                        + 2.5 * f["escalation"] + 2.0 * f["supply_chain"],
                        [f"{f['unauth_completed']} completed out-of-role access(es)"] * bool(f["unauth_completed"])
                        + [f"{f['rare']} behavior(s) rare for its role"] * bool(f["rare"])
                        + ["tried to widen its authority or impersonate another agent"] * f["escalation"]
                        + ["used tooling outside the trusted supply chain"] * f["supply_chain"]),
        "colluding_member": (3.0 * (f["in_chain"] and not f["chain_origin"]) + 2.0 * (f["in_chain"] and f["exfil"]),
                             ["received or relayed restricted data in a chain"] * (f["in_chain"] and not f["chain_origin"])
                             + ["sent chained data outside"] * (f["in_chain"] and f["exfil"])),
        "misconfiguration": ((1.5 if f["unauth_denied"] and not f["unauth_completed"] and not f["exfil"] and not f["in_chain"] else 0.0)
                             + (0.5 if f["unauth_total"] == 1 else 0.0),
                             ["only denied attempts, nothing left the system"] * bool(f["unauth_denied"] and not f["unauth_completed"])),
        "benign_variation": ((1.0 if not f["rules"] else 0.1) + (0.5 if f["rare"] <= 1 else 0.0),
                             ["no rule fired"] * (not f["rules"])),
    }
    total = sum(score for score, _ in raw.values()) or 1.0
    out = [Hypothesis(hypothesis=k, label=HYPOTHESES[k], score=round(score / total, 3), supporting=support)
           for k, (score, support) in raw.items()]
    return sorted(out, key=lambda h: h.score, reverse=True)


def assess(run_id: str, events: list[NormalizedEvent], agents: list[Agent], alerts: list[Alert],
           rules: list[DetectionRule]) -> list[AgentAssessment]:
    anomaly_rule = next((r for r in rules if r.rule_id == "SG-004"), None)
    profile = (anomaly_rule.params.get("profile") if anomaly_rule and anomaly_rule.enabled else None) or baseline.empty_profile()
    watch_bits = float(anomaly_rule.params.get("watch_bits", 6.0)) if anomaly_rule else 6.0
    restricted = set(next((r.params.get("restricted_resources", []) for r in rules if r.rule_id == "SG-001"), []))
    behaviors = baseline.agent_behaviors(events)
    by_id = {e.event_id: e for e in events}

    agent_alerts: dict[str, list[Alert]] = defaultdict(list)
    for al in alerts:
        for aid in al.agent_ids:
            agent_alerts[aid].append(al)

    out = []
    for a in agents:
        bits, rare = baseline.score_agent(profile, a.role, behaviors.get(a.agent_id, {}))
        own = agent_alerts.get(a.agent_id, [])
        odds = PRIOR / (1 - PRIOR)
        evidence = []
        strongest: dict[str, Alert] = {}
        for al in own:  # one factor per rule, strongest severity wins
            if al.rule_id == "SG-004":
                continue  # anomaly enters below as its own factor
            cur = strongest.get(al.rule_id)
            if cur is None or SEVERITY_LR[al.severity] > SEVERITY_LR[cur.severity]:
                strongest[al.rule_id] = al
        for rule_id, al in sorted(strongest.items()):
            lr = SEVERITY_LR[al.severity]
            odds *= lr
            evidence.append(f"{rule_id} {al.rule_name} ({al.severity}): x{lr:g}")
        if bits > 0:
            lr = anomaly_lr(bits)
            odds *= lr
            evidence.append(f"Behavioral anomaly {bits} bits: x{lr:.1f}")
        risk = round(odds / (1 + odds), 4)

        sg1 = [by_id[eid] for al in own if al.rule_id == "SG-001" for eid in al.event_ids if eid in by_id]
        chains = [al for al in own if al.rule_id in ("SG-003", "SG-005")]  # direct or hidden hand-off
        fired = {al.rule_id for al in own}
        facts = {
            "rules": bool(strongest),
            "rare": len(rare),
            "unauth_total": len(sg1),
            "unauth_completed": sum(1 for e in sg1 if e.status == "success"),
            "unauth_denied": sum(1 for e in sg1 if e.status == "denied"),
            "exfil": any(al.rule_id == "SG-002" for al in own),
            "in_chain": bool(chains),
            "chain_origin": any(al.agent_ids and al.agent_ids[0] == a.agent_id for al in chains),
            "hidden_channel": any(al.rule_id == "SG-005" for al in own),
            "oversight": any(al.rule_id == "SG-006" for al in own),
            "self_copy": any(al.rule_id == "SG-007" for al in own),
            "tripwire": any(al.rule_id == "SG-009" for al in own),
            "escalation": any(al.rule_id == "SG-008" for al in own),
            "power": "SG-011" in fired,
            "hijacked": "SG-012" in fired,
            "deceptive": "SG-014" in fired,
            "gaming": "SG-015" in fired,
            "salami": "SG-016" in fired,
            "coercion": "SG-017" in fired,
            "loop": "SG-018" in fired,
            "supply_chain": "SG-019" in fired,
            "steg": "SG-020" in fired,
            "permitted_restricted_read": any(
                e.agent_id == a.agent_id and e.event_type == "resource_access" and e.resource in restricted
                and e.resource in a.permissions and e.status == "success" for e in events),
        }
        lvl = level(risk, bits, watch_bits)
        hyps = _hypotheses(facts) if lvl != "low" else []
        out.append(AgentAssessment(
            run_id=run_id, agent_id=a.agent_id, role=a.role, prior=PRIOR, risk=risk, level=lvl,
            anomaly_bits=bits, rare_behaviors=[RareBehavior(**r) for r in rare], evidence=evidence,
            alert_ids=[al.alert_id for al in own], hypotheses=hyps,
            best_explanation=hyps[0].label if hyps else None,
        ))
    # Attention: highest risk first.
    return sorted(out, key=lambda x: (-x.risk, -x.anomaly_bits, x.agent_id))
