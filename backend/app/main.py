"""SwarmGuard FastAPI application."""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.adapters import available_adapters
from app.config import get_settings
from app.module_info import MODULES, module_info
from app.modules.simulator.world import SCENARIOS
from app.schemas import (
    AGENT_COUNTS, BaselineTrainRequest, CollectRequest, DetectionRule, DetectRequest, EvaluateRequest, RespondRequest, ResponsePolicy,
    ScenarioConfig, SuiteRequest,
)
from app.services.pipeline import NotFound, Pipeline
from app.storage import get_store


def get_pipeline() -> Pipeline:
    return Pipeline(get_store())


@asynccontextmanager
async def lifespan(app: FastAPI):
    get_pipeline().seed_defaults()
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
@app.post("/api/simulate")
def simulate(config: ScenarioConfig, p: Pipeline = P):
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
