"""Integration-style tests for the Engine.

These tests exercise the full analyze_context() pipeline using pre-built
ScanContext objects (no network I/O).
"""
import pytest
from core.engine import Engine
from core.analyzer_registry import AnalyzerRegistry
from tests.conftest import make_context


@pytest.fixture
def engine():
    """Return a passive-only Engine instance (excludes active analyzers)."""
    active = set(AnalyzerRegistry.get_analyzers_by_type("active"))
    return Engine(exclude_analyzers=active)


@pytest.mark.asyncio
async def test_engine_analyze_empty_context_returns_list(engine):
    """analyze_context must always return a list, even with empty context."""
    ctx = make_context()
    result = await engine.analyze_context(ctx)
    assert isinstance(result, list)


@pytest.mark.asyncio
async def test_engine_detects_nginx_from_server_header(engine):
    ctx = make_context(headers={"server": "nginx/1.24.0"})
    result = await engine.analyze_context(ctx)
    names = {d.name for d in result}
    assert "Nginx" in names


@pytest.mark.asyncio
async def test_engine_detects_php_from_powered_by_header(engine):
    ctx = make_context(headers={"x-powered-by": "PHP/8.1.0"})
    result = await engine.analyze_context(ctx)
    names = {d.name for d in result}
    assert "PHP" in names


@pytest.mark.asyncio
async def test_engine_detects_wordpress_cookie(engine):
    ctx = make_context(cookies={"wp-settings-1": "value"})
    result = await engine.analyze_context(ctx)
    names = {d.name for d in result}
    assert "WordPress" in names


@pytest.mark.asyncio
async def test_engine_confidence_capped_at_one(engine):
    """All returned detections must have confidence <= 1.0."""
    ctx = make_context(
        headers={"server": "nginx/1.24.0", "x-powered-by": "PHP/8.1.0"},
        cookies={"wordpress_logged_in_abc": "value"},
    )
    result = await engine.analyze_context(ctx)
    for detection in result:
        assert detection.confidence <= 1.0, (
            f"{detection.name} has confidence {detection.confidence} > 1.0"
        )


@pytest.mark.asyncio
async def test_engine_detections_sorted_by_confidence(engine):
    """Results should be sorted descending by confidence."""
    ctx = make_context(
        headers={"server": "nginx/1.24.0", "x-powered-by": "PHP/8.1.0"},
    )
    result = await engine.analyze_context(ctx)
    for i in range(len(result) - 1):
        assert result[i].confidence >= result[i + 1].confidence


@pytest.mark.asyncio
async def test_engine_each_detection_has_evidence(engine):
    """Every detection must carry an evidence object with type populated."""
    ctx = make_context(headers={"server": "nginx/1.24.0"})
    result = await engine.analyze_context(ctx)
    for detection in result:
        assert detection.evidence is not None
        assert detection.evidence.type


@pytest.mark.asyncio
async def test_engine_no_duplicate_technology_names(engine):
    """After aggregation, each technology name must appear at most once."""
    ctx = make_context(
        headers={"server": "nginx/1.24.0", "x-powered-by": "PHP/8.1.0"},
    )
    result = await engine.analyze_context(ctx)
    names = [d.name for d in result]
    assert len(names) == len(set(names)), f"Duplicate detections: {names}"


@pytest.mark.asyncio
async def test_engine_favicon_hash_detection(engine):
    """FaviconAnalyzer should trigger when the hash matches a rule."""
    from rules.rules_loader import load_rules
    # Find a favicon hash rule to test with
    rules = load_rules()
    favicon_rules = [
        (tech.name, rule.value)
        for tech in rules
        for rule in tech.evidence_rules
        if rule.type == "favicon_hash" and rule.value
    ]
    if not favicon_rules:
        pytest.skip("No favicon_hash rules found in YAML files")

    tech_name, hash_value = favicon_rules[0]
    ctx = make_context(favicon_hash=hash_value)
    result = await engine.analyze_context(ctx)
    names = {d.name for d in result}
    assert tech_name in names
