"""Agent relationship graph built with NetworkX."""
from __future__ import annotations

from collections import Counter

import networkx as nx

from app.schemas import Agent, AgentGraph, Alert, GraphEdge, GraphNode, NormalizedEvent


def build_graph(run_id: str, events: list[NormalizedEvent], agents: list[Agent], alerts: list[Alert]) -> AgentGraph:
    g = nx.DiGraph()
    roles = {a.agent_id: a.role for a in agents}
    for a in agents:
        g.add_node(a.agent_id, kind="agent")
    flagged = {aid for al in alerts for aid in al.agent_ids}
    activity = Counter(e.agent_id for e in events)

    for e in events:
        if e.event_type == "message" and e.target:
            kind = "message"
        elif e.event_type == "data_transfer" and e.target:
            kind = "data_transfer"
        else:
            continue
        for node in (e.agent_id, e.target):
            if node not in g:
                g.add_node(node, kind="external" if node.startswith("external:") else "agent")
        if g.has_edge(e.agent_id, e.target):
            g[e.agent_id][e.target]["event_ids"].append(e.event_id)
        else:
            g.add_edge(e.agent_id, e.target, kind=kind, event_ids=[e.event_id])

    degree = nx.degree_centrality(g) if g.number_of_nodes() > 1 else {}
    between = nx.betweenness_centrality(g) if g.number_of_nodes() > 2 else {}
    nodes = [
        GraphNode(
            id=n,
            kind=data.get("kind", "agent"),
            role=roles.get(n),
            flagged=n in flagged,
            event_count=activity.get(n, 0),
            degree_centrality=round(degree.get(n, 0.0), 4),
            betweenness=round(between.get(n, 0.0), 4),
        )
        for n, data in g.nodes(data=True)
    ]
    edges = [
        GraphEdge(source=u, target=v, kind=d["kind"], count=len(d["event_ids"]), event_ids=d["event_ids"])
        for u, v, d in g.edges(data=True)
    ]
    return AgentGraph(run_id=run_id, nodes=nodes, edges=edges)
