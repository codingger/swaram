"""The live-guard speedups are pure caches: they must never leak state between callers or event lists."""
from app.modules.detection.advanced_rules import encoding_artifacts
from app.modules.detection.evidence import LogCoverage
from app.modules.simulator.engine import run_simulation
from app.modules.collector.normalizer import collect
from app.schemas import ScenarioConfig


def test_cached_text_scan_hands_out_independent_lists():
    text = "status ok\u200b\u200c\u200b"
    first = encoding_artifacts(text)
    first.append("unusually long message")  # SG-020 appends to the list it gets
    assert encoding_artifacts(text) == ["zero-width characters"]


def test_coverage_is_shared_within_one_list_and_never_across_lists():
    sim = run_simulation(ScenarioConfig(scenario_id="normal_collaboration", drop_rate=0.3, persist=False))
    events = collect([e.model_dump(mode="json") for e in sim.events], run_id=sim.run.run_id, agents=sim.agents).events
    assert LogCoverage.of(events) is LogCoverage.of(events)
    shorter = events[:-5]
    assert LogCoverage.of(shorter) is not LogCoverage.of(events)
    assert LogCoverage.of(shorter).seqs == LogCoverage(shorter).seqs
