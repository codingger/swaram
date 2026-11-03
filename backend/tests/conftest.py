from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from app.config import FIXTURES_DIR
from app.modules.collector.normalizer import collect
from app.modules.simulator.engine import run_simulation
from app.schemas import ScenarioConfig
from app.services.pipeline import Pipeline
from app.storage.sqlite_store import SQLiteStore

BASE_TIME = datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc)


def simulate(scenario: str, agents: int = 5, seed: int = 7, gateway: str = "monitor", drop: float = 0.0, run_id: str = "run-test0001"):
    cfg = ScenarioConfig(scenario_id=scenario, agent_count=agents, seed=seed, gateway_mode=gateway, drop_rate=drop, persist=False)
    return run_simulation(cfg, run_id=run_id, base_time=BASE_TIME)


def normalize(sim):
    return collect([e.model_dump(mode="json") for e in sim.events], run_id=sim.run.run_id, agents=sim.agents).events


def load_jsonl(name: str) -> list:
    return [json.loads(line) for line in (FIXTURES_DIR / name).read_text(encoding="utf-8").splitlines() if line.strip()]


@pytest.fixture
def store():
    return SQLiteStore(":memory:")


@pytest.fixture
def pipeline(store):
    p = Pipeline(store)
    p.seed_defaults()
    return p
