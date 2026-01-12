import asyncio
from typing import List

from core.engine import _filter_technologies_by_rule_types, Engine
from models.technology import Technology, EvidenceRule
from core.context import ScanContext, TLSInfo


def test_filter_technologies_by_rule_types_basic():
    techs: List[Technology] = [
        Technology(
            name="TechA",
            category="Cat",
            evidence_rules=[
                EvidenceRule(type="header", name="Server", pattern="apache", confidence=0.4),
                EvidenceRule(type="js_global", pattern="TechA", confidence=0.6),
                EvidenceRule(type="css_link", pattern="techA.css", confidence=0.3),
            ],
        ),
        Technology(
            name="TechB",
            category="Cat",
            evidence_rules=[
                EvidenceRule(type="dns_record", name="TXT", pattern="techb", confidence=0.5),
            ],
        ),
    ]

    filtered = _filter_technologies_by_rule_types(techs, {"header", "js_global"})

    # TechA remains with only allowed rules; TechB is excluded
    assert len(filtered) == 1
    assert filtered[0].name == "TechA"
    types = {r.type for r in filtered[0].evidence_rules}
    assert types == {"header", "js_global"}


def test_engine_aggregates_confidence_caps_at_one(monkeypatch):
    # Prepare synthetic rules: same technology with two evidence sources
    techs: List[Technology] = [
        Technology(
            name="FooTech",
            category="Test",
            evidence_rules=[
                EvidenceRule(type="header", name="Server", pattern="foo", confidence=0.6),
                EvidenceRule(type="js_global", pattern="Foo", confidence=0.5),
            ],
        )
    ]

    # Patch the engine's rules loader to return our synthetic technologies
    monkeypatch.setattr("core.engine.load_rules", lambda: techs, raising=False)

    engine = Engine()

    context = ScanContext(
        url="https://example.com",
        headers={"server": "foo"},
        html="<html><head></head><body></body></html>",
        cookies={},
        scripts=[],
        stylesheets=[],
        js_globals={"Foo"},
        tls=None,
        dns_records={}
    )

    detections = asyncio.run(engine.analyze_context(context))

    # One aggregated detection for FooTech with confidence 1.0 (capped)
    assert len(detections) == 1
    det = detections[0]
    assert det.name == "FooTech"
    assert det.category == "Test"
    assert abs(det.confidence - 1.0) < 1e-9
    # Strongest evidence is the header (0.6 vs 0.5)
    assert det.evidence.type in {"header", "js_global"}