"""SwarmGuard FastAPI application."""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import Body, Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.adapters import available_adapters
from app.config import get_settings
from app.module_info import MODULES, module_info
from app.modules.simulator.world import SCENARIOS
from app.schemas import (
    AGENT_COUNTS, BaselineTrainRequest, CollectRequest, ReplayRequest, DetectionRule, DetectRequest, EvaluateRequest, RespondRequest, ResponsePolicy,
    ScenarioConfig, SuiteRequest,
)
from app.services.pipeline import NotFound, Pipeline
from app.storage import get_store


def get_pipeline() -> Pipeline:
    return Pipeline(get_store())


@asynccontextmanager
async def lifespan(app: FastAPI):
    from app.services import notify
    from app.services.live_hub import get_hub

    get_pipeline().seed_defaults()
    notify.install(get_hub())  # opt-in: SWARMGUARD_WEBHOOK_URL
    yield


app = FastAPI(title="SwarmGuard", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(NotFound)
async def not_found(_: Request, exc: NotFound):
    return JSONResponse(status_code=404, content={"detail": str(exc)})


@app.exception_handler(ValueError)
async def bad_request(_: Request, exc: ValueError):
    return JSONResponse(status_code=400, content={"detail": str(exc)})


P = Depends(get_pipeline)


# ------------------------------------------------------------------ meta
@app.get("/api/health")
def health(p: Pipeline = P) -> dict[str, Any]:
    return {"ok": True, "storage": p.store.backend, "workspace": p.store.workspace}


@app.get("/api/gemini/quota")
def gemini_quota() -> dict[str, Any]:
    """Gemini calls used today, what's left, when Google resets it, and what a run costs."""
    from app.services.quota import quota_status

    return quota_status()


@app.get("/api/meta")
def meta() -> dict[str, Any]:
    return {"scenarios": [s.model_dump() for s in SCENARIOS], "agent_counts": list(AGENT_COUNTS),
            "agent_backends": available_adapters()}


@app.get("/api/modules/{name}")
def get_module_info(name: str) -> dict[str, Any]:
    if name not in MODULES:
        raise HTTPException(404, f"unknown module {name}")
    return module_info(name)


# ------------------------------------------------------------------ runs
@app.get("/api/runs")
def list_runs(limit: int = 50, p: Pipeline = P):
    return p.list_runs(limit)


@app.get("/api/runs/{run_id}")
def get_run(run_id: str, p: Pipeline = P):
    return p.get_run(run_id)


@app.get("/api/runs/{run_id}/agents")
def run_agents(run_id: str, p: Pipeline = P):
    return p.agents(run_id)


@app.get("/api/runs/{run_id}/raw-events")
def run_raw_events(run_id: str, p: Pipeline = P):
    return p.raw_events(run_id)


@app.get("/api/runs/{run_id}/normalized-events")
def run_normalized_events(run_id: str, p: Pipeline = P):
    return p.normalized_events(run_id)


@app.get("/api/runs/{run_id}/alerts")
def run_alerts(run_id: str, p: Pipeline = P):
    return p.alerts(run_id)


@app.get("/api/runs/{run_id}/graph")
def run_graph(run_id: str, p: Pipeline = P):
    return p.graph(run_id).graph


@app.get("/api/runs/{run_id}/responses")
def run_responses(run_id: str, p: Pipeline = P):
    return p.responses(run_id)


@app.get("/api/runs/{run_id}/dashboard")
def run_dashboard(run_id: str, p: Pipeline = P):
    return p.dashboard(run_id)


@app.post("/api/runs/{run_id}/pipeline")
def run_pipeline(run_id: str, p: Pipeline = P):
    """Automatic trigger: collect -> detect -> respond -> evaluate."""
    return p.run_all(run_id)


# ------------------------------------------------------------------ modules
# ------------------------------------------------------------------ live streaming (for the live UI)
@app.post("/api/runs/start")
def start_run(config: ScenarioConfig, p: Pipeline = P) -> dict[str, Any]:
    """Start a run in the background; watch it on the /api/live WebSocket. Returns at once."""
    if config.workspace_dir:
        raise HTTPException(400, "workspace_dir can't be set through the API")
    return {"run_id": p.start_run(config), "stream": "/api/live"}


@app.get("/api/live/active")
def active_runs() -> list[dict[str, Any]]:
    from app.services.pipeline import ACTIVE_RUNS

    return list(ACTIVE_RUNS.values())


@app.websocket("/api/live")
async def live(ws: WebSocket):
    """Every event, detection, containment and quarantine, pushed as it happens.

    Query: ?run_id=… to follow one run; ?since=<seq> to replay what you missed (default: the recent history).
    """
    import asyncio

    from app.services.live_hub import get_hub

    await ws.accept()
    hub = get_hub()
    run_id = ws.query_params.get("run_id") or None
    since = int(ws.query_params.get("since") or 0)
    sub = hub.subscribe(asyncio.get_running_loop(), run_id)
    try:
        await ws.send_json({"type": "hello", "seq": 0, "run_id": run_id, "data": {"subscribers": hub.subscribers}})
        for msg in hub.replay(run_id, since):
            await ws.send_json(msg)
        while True:
            await ws.send_json(await sub.queue.get())
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        hub.unsubscribe(sub)


# ------------------------------------------------------------------ live ingest (real agents outside the simulator)
@app.post("/api/ingest/sessions")
def ingest_open(body: dict[str, Any], p: Pipeline = P) -> dict[str, Any]:
    from app.services import ingest

    return ingest.open_session(p, body.get("name") or "external", body.get("agents") or [],
                               body.get("live_guard", "contain"), float(body.get("pause_at", 0.6)))


@app.post("/api/ingest/{run_id}/gate")
def ingest_gate(run_id: str, body: dict[str, Any]) -> dict[str, Any]:
    """Ask BEFORE acting: {"allow": false, "reason": ...} means the agent must not do it."""
    from app.services import ingest

    if not body.get("agent_id"):
        raise HTTPException(400, "agent_id is required")
    return ingest.session(run_id).gate(body)


@app.post("/api/ingest/{run_id}/events")
def ingest_events(run_id: str, body: Any = Body(...), format: str | None = None, p: Pipeline = P) -> dict[str, Any]:
    """Raw events (a list or one object), or ?format=otel|langsmith to send OpenTelemetry spans / LangSmith runs."""
    from app.modules.collector.formats import convert
    from app.services import ingest

    if format:
        events, _ = convert(format, body, run_id)
    else:
        events = body if isinstance(body, list) else [body]
    return ingest.add_events(p, run_id, events)


@app.post("/api/convert")
def convert_logs(body: Any = Body(...), format: str = "otel", run_id: str = "run-imported") -> dict[str, Any]:
    """Preview how OpenTelemetry spans (format=otel) or LangSmith runs (format=langsmith) map to SwarmGuard events."""
    from app.modules.collector.formats import convert

    events, agents = convert(format, body, run_id)
    return {"events": events, "agents": agents}


@app.post("/api/ingest/{run_id}/finish")
def ingest_finish(run_id: str, p: Pipeline = P) -> dict[str, Any]:
    from app.services import ingest

    return ingest.finish(p, run_id)


# ------------------------------------------------------------------ review queue (Security Response)
@app.get("/api/reviews")
def reviews(status: str | None = None, run_id: str | None = None, p: Pipeline = P) -> list[dict[str, Any]]:
    from app.services import review

    return review.items(p.store, status, run_id)


@app.post("/api/reviews/{review_id}")
def decide_review(review_id: str, body: dict[str, Any], p: Pipeline = P) -> dict[str, Any]:
    """{"decision": "release" | "confirm", "note": "..."}"""
    from app.services import review

    return review.decide(p.store, review_id, body.get("decision", ""), body.get("note"))


@app.get("/api/runs/{run_id}/integrity")
def run_integrity(run_id: str, p: Pipeline = P) -> dict[str, Any]:
    """Tamper evidence: was any stored event edited, deleted or reordered since collection?"""
    return p.integrity(run_id)


@app.post("/api/simulate")
def simulate(config: ScenarioConfig, p: Pipeline = P):
    if config.workspace_dir:
        # Agents write files into the workspace; only local scripts may choose where that is on disk.
        raise HTTPException(400, "workspace_dir can't be set through the API")
    return p.simulate(config)


@app.post("/api/collect")
def collect(req: CollectRequest, p: Pipeline = P):
    if not req.run_id and req.events is None:
        raise HTTPException(400, "provide run_id or events")
    return p.collect(req.run_id, req.events, req.persist)


@app.post("/api/detect")
def detect(req: DetectRequest, p: Pipeline = P):
    return p.detect(req.run_id, req.persist)


@app.get("/api/runs/{run_id}/assessments")
def run_assessments(run_id: str, p: Pipeline = P):
    """Per-agent Bayesian risk + best explanation, ranked by risk."""
    return p.assessments(run_id)


@app.get("/api/runs/{run_id}/audit-queue")
def run_audit_queue(run_id: str, p: Pipeline = P):
    """Risk-ranked sample of actions for human / trusted-model review (not alerts)."""
    return p.audit_queue(run_id)


@app.get("/api/runs/{run_id}/live-report")
def run_live_report(run_id: str, p: Pipeline = P):
    """What the live guard saw and stopped while the run was happening."""
    return p.live_report(run_id)


@app.get("/api/detection/replay-cases")
def replay_cases():
    """The 26 labeled attacks and 12 benign look-alikes that can be replayed into a live run."""
    from app.modules.detection.benchmark import case_catalog

    return case_catalog()


@app.post("/api/detection/replay")
def replay(req: ReplayRequest, p: Pipeline = P):
    """Plant one case into a fresh realistic run, stream it through the live guard, save it and run the pipeline."""
    return p.replay(req)


@app.post("/api/detection/benchmark")
def detection_benchmark(full: bool = False, p: Pipeline = P):
    """Accuracy on planted attacks + benign look-alikes. Quick by default (~150 trials); full=true runs ~1,400."""
    from app.modules.detection.benchmark import ALL_CASES, run_benchmark
    from app.modules.detection.rules import run_rules

    res = run_benchmark(p.rules(), run_rules, drop_rates=(0.0, 0.1, 0.3, 0.5) if full else (0.0, 0.3),
                        agent_counts=(5, 10, 20) if full else (5,), seeds=range(1, 4) if full else range(1, 3))
    res["cases_info"] = {c.name: {"threat": c.threat, "benign": c.benign} for c in ALL_CASES}
    return res


@app.get("/api/detection/baseline")
def detection_baseline(p: Pipeline = P):
    return p.baseline_summary()


@app.post("/api/detection/baseline")
def train_detection_baseline(req: BaselineTrainRequest, p: Pipeline = P):
    """Retrain from synthetic normal runs, or fold in one run confirmed clean (continual learning)."""
    return p.train_baseline(req)


@app.get("/api/detection-rules")
def detection_rules(p: Pipeline = P):
    return p.rules()


@app.put("/api/detection-rules/{rule_id}")
def update_rule(rule_id: str, rule: DetectionRule, p: Pipeline = P):
    if rule.rule_id != rule_id:
        raise HTTPException(400, "rule_id mismatch")
    return p.save_rule(rule)


@app.post("/api/respond")
def respond(req: RespondRequest, p: Pipeline = P):
    return p.respond(req.run_id, req.policy, req.persist)


@app.get("/api/response-policies/{policy_id}")
def get_policy(policy_id: str, p: Pipeline = P):
    return p.policy(policy_id)


@app.put("/api/response-policies/{policy_id}")
def put_policy(policy_id: str, policy: ResponsePolicy, p: Pipeline = P):
    if policy.policy_id != policy_id:
        raise HTTPException(400, "policy_id mismatch")
    return p.save_policy(policy)


@app.post("/api/evaluate")
def evaluate(req: EvaluateRequest, p: Pipeline = P):
    return p.evaluate(req.run_id, req.persist)


@app.post("/api/evaluate/suite")
def evaluate_suite(req: SuiteRequest, p: Pipeline = P):
    return p.suite(req)


@app.get("/api/evaluations")
def evaluations(p: Pipeline = P):
    return p.evaluations()
