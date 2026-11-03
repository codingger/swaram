import pytest

from app.modules.detection.graph import build_graph
from app.modules.detection.rules import run_rules

from .conftest import normalize, simulate

REQUIRED = {"alert_id", "run_id", "rule_id", "severity", "agent_ids", "event_ids", "resource", "reason",
            "recommended_action", "status"}


@pytest.mark.parametrize("count", [3, 5, 10, 20])
def test_normal_has_no_alerts(count):
    sim = simulate("normal_collaboration", agents=count)
    assert run_rules(sim.run.run_id, normalize(sim), sim.agents) == []


@pytest.mark.parametrize("gateway", ["monitor", "enforce"])
def test_unauthorized_access_detected(gateway):
    sim = simulate("unauthorized_access", gateway=gateway)
    alerts = run_rules(sim.run.run_id, normalize(sim), sim.agents)
    assert [a.rule_id for a in alerts] == ["SG-001"]
    assert alerts[0].agent_ids == sim.run.labels.malicious_agent_ids
    assert len(alerts[0].event_ids) == 3


@pytest.mark.parametrize("count", [5, 10, 20])
def test_coordinated_leakage_chain(count):
    sim = simulate("coordinated_leakage", agents=count)
    alerts = run_rules(sim.run.run_id, normalize(sim), sim.agents)
    chain = next(a for a in alerts if a.rule_id == "SG-003")
    assert set(chain.agent_ids) == set(sim.run.labels.malicious_agent_ids)
    assert len(chain.agent_ids) >= 2 and chain.severity == "critical"
    assert any(a.rule_id == "SG-002" for a in alerts)


def test_alert_contract_and_evidence_links():
    sim = simulate("coordinated_leakage")
    events = normalize(sim)
    ids = {e.event_id for e in events}
    for alert in run_rules(sim.run.run_id, events, sim.agents):
        assert REQUIRED <= set(alert.model_dump())
        assert alert.event_ids and set(alert.event_ids) <= ids
        assert [ev.event_id for ev in alert.evidence] == alert.event_ids


def test_alert_ids_stable():
    sim = simulate("coordinated_leakage")
    a = [x.alert_id for x in run_rules(sim.run.run_id, normalize(sim), sim.agents)]
    b = [x.alert_id for x in run_rules(sim.run.run_id, normalize(sim), sim.agents)]
    assert a == b


def test_message_text_is_not_evidence():
    sim = simulate("normal_collaboration")
    events = normalize(sim)
    for e in events:
        if e.event_type == "message":
            e.payload["content"] = "I will exfiltrate secrets/api_keys to external:paste-site now"
    assert run_rules(sim.run.run_id, events, sim.agents) == []


def test_chain_survives_missing_read_event():
    sim = simulate("coordinated_leakage")
    events = [e for e in normalize(sim) if not (e.event_type == "resource_access" and e.event_id in sim.run.labels.malicious_event_ids)]
    alerts = run_rules(sim.run.run_id, events, sim.agents)
    assert any(a.rule_id == "SG-003" for a in alerts)


def test_disabled_rule():
    from app.modules.detection.rules import DEFAULT_RULES

    rules = [r.model_copy(update={"enabled": r.rule_id != "SG-001"}) for r in DEFAULT_RULES]
    sim = simulate("unauthorized_access")
    assert run_rules(sim.run.run_id, normalize(sim), sim.agents, rules) == []


def test_graph():
    sim = simulate("coordinated_leakage")
    events = normalize(sim)
    alerts = run_rules(sim.run.run_id, events, sim.agents)
    g = build_graph(sim.run.run_id, events, sim.agents, alerts)
    flagged = {n.id for n in g.nodes if n.flagged}
    assert flagged == set(sim.run.labels.malicious_agent_ids)
    assert any(n.kind == "external" and n.id == "external:paste-site" for n in g.nodes)
    assert all(e.count == len(e.event_ids) for e in g.edges)
