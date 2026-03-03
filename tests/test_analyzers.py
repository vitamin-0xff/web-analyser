"""Tests for CookiesAnalyzer, FaviconAnalyzer, and DetectionAggregator."""
import pytest
from analyzers.cookies import CookiesAnalyzer
from analyzers.favicon import FaviconAnalyzer
from core.detection_aggregator import DetectionAggregator
from models.detection import Detection, Evidence
from models.technology import Technology, EvidenceRule
from tests.conftest import make_context


# ---------------------------------------------------------------------------
# CookiesAnalyzer
# ---------------------------------------------------------------------------

def _cookie_rule(tech_name: str, *, name: str = None, pattern: str = None, confidence: float = 0.8):
    return Technology(
        name=tech_name,
        category="CMS",
        evidence_rules=[
            EvidenceRule(type="cookie", name=name, pattern=pattern, confidence=confidence)
        ],
    )


@pytest.mark.asyncio
async def test_cookies_analyzer_exact_name_match():
    rule = _cookie_rule("WordPress", name="wordpress_logged_in")
    analyzer = CookiesAnalyzer([rule])
    ctx = make_context(cookies={"wordpress_logged_in": "xyz"})

    result = await analyzer.analyze(ctx)

    assert len(result) == 1
    assert result[0].name == "WordPress"
    assert result[0].evidence.type == "cookie"
    assert result[0].evidence.name == "wordpress_logged_in"


@pytest.mark.asyncio
async def test_cookies_analyzer_pattern_match():
    rule = _cookie_rule("WordPress", pattern=r"wordpress_logged_in_\w+")
    analyzer = CookiesAnalyzer([rule])
    ctx = make_context(cookies={"wordpress_logged_in_abc123": "val"})

    result = await analyzer.analyze(ctx)

    assert len(result) == 1
    assert result[0].name == "WordPress"


@pytest.mark.asyncio
async def test_cookies_analyzer_no_match():
    rule = _cookie_rule("Django", name="csrftoken")
    analyzer = CookiesAnalyzer([rule])
    ctx = make_context(cookies={"session": "abc"})

    result = await analyzer.analyze(ctx)

    assert result == []


@pytest.mark.asyncio
async def test_cookies_analyzer_empty_cookies():
    rule = _cookie_rule("Django", name="csrftoken")
    analyzer = CookiesAnalyzer([rule])
    ctx = make_context(cookies={})

    result = await analyzer.analyze(ctx)

    assert result == []


# ---------------------------------------------------------------------------
# FaviconAnalyzer
# ---------------------------------------------------------------------------

WORDPRESS_FAVICON_HASH = "d41d8cd98f00b204e9800998ecf8427e"


def _favicon_rule(tech_name: str, hash_value: str, confidence: float = 0.95):
    return Technology(
        name=tech_name,
        category="CMS",
        evidence_rules=[
            EvidenceRule(type="favicon_hash", value=hash_value, confidence=confidence)
        ],
    )


@pytest.mark.asyncio
async def test_favicon_analyzer_hash_match():
    rule = _favicon_rule("WordPress", WORDPRESS_FAVICON_HASH)
    analyzer = FaviconAnalyzer([rule])
    ctx = make_context(favicon_hash=WORDPRESS_FAVICON_HASH)

    result = await analyzer.analyze(ctx)

    assert len(result) == 1
    assert result[0].name == "WordPress"
    assert result[0].evidence.type == "favicon_hash"
    assert result[0].evidence.value == WORDPRESS_FAVICON_HASH


@pytest.mark.asyncio
async def test_favicon_analyzer_hash_mismatch():
    rule = _favicon_rule("WordPress", WORDPRESS_FAVICON_HASH)
    analyzer = FaviconAnalyzer([rule])
    ctx = make_context(favicon_hash="0000000000000000000000000000000a")

    result = await analyzer.analyze(ctx)

    assert result == []


@pytest.mark.asyncio
async def test_favicon_analyzer_no_hash_skipped():
    """When favicon_hash is None, return an empty list without error."""
    rule = _favicon_rule("WordPress", WORDPRESS_FAVICON_HASH)
    analyzer = FaviconAnalyzer([rule])
    ctx = make_context(favicon_hash=None)

    result = await analyzer.analyze(ctx)

    assert result == []


@pytest.mark.asyncio
async def test_favicon_analyzer_case_insensitive():
    """Hash comparison must be case-insensitive."""
    rule = _favicon_rule("WordPress", WORDPRESS_FAVICON_HASH.upper())
    analyzer = FaviconAnalyzer([rule])
    ctx = make_context(favicon_hash=WORDPRESS_FAVICON_HASH.lower())

    result = await analyzer.analyze(ctx)

    assert len(result) == 1


# ---------------------------------------------------------------------------
# DetectionAggregator
# ---------------------------------------------------------------------------

def _detection(name: str, category: str, confidence: float, evidence_type: str) -> Detection:
    return Detection(
        name=name,
        category=category,
        confidence=confidence,
        evidence=Evidence(type=evidence_type, value="test"),
    )


def test_aggregator_empty_input():
    assert DetectionAggregator.aggregate([]) == []


def test_aggregator_single_detection_unchanged():
    d = _detection("Nginx", "Web Server", 0.8, "header")
    result = DetectionAggregator.aggregate([d])
    assert len(result) == 1
    assert result[0].name == "Nginx"
    assert result[0].confidence == 0.8


def test_aggregator_merges_same_technology():
    """Two detections of the same technology are merged into one."""
    d1 = _detection("WordPress", "CMS", 0.7, "header")
    d2 = _detection("WordPress", "CMS", 0.6, "cookie")
    result = DetectionAggregator.aggregate([d1, d2])
    assert len(result) == 1
    assert result[0].name == "WordPress"


def test_aggregator_boosts_confidence_with_multiple_sources():
    """Confidence must be boosted when multiple evidence types agree."""
    d1 = _detection("WordPress", "CMS", 0.7, "header")
    d2 = _detection("WordPress", "CMS", 0.7, "cookie")
    result = DetectionAggregator.aggregate([d1, d2])
    # With two sources, multiplier is 1.15 -> 0.7 * 1.15 = 0.805
    assert result[0].confidence > 0.7


def test_aggregator_caps_confidence_at_one():
    d1 = _detection("WordPress", "CMS", 0.9, "header")
    d2 = _detection("WordPress", "CMS", 0.9, "cookie")
    d3 = _detection("WordPress", "CMS", 0.9, "html_pattern")
    result = DetectionAggregator.aggregate([d1, d2, d3])
    assert result[0].confidence <= 1.0


def test_aggregator_keeps_distinct_technologies_separate():
    d1 = _detection("Nginx", "Web Server", 0.9, "header")
    d2 = _detection("WordPress", "CMS", 0.8, "cookie")
    result = DetectionAggregator.aggregate([d1, d2])
    assert len(result) == 2
    names = {d.name for d in result}
    assert "Nginx" in names
    assert "WordPress" in names


def test_aggregator_sorts_by_confidence_descending():
    d1 = _detection("WordPress", "CMS", 0.5, "header")
    d2 = _detection("Nginx", "Web Server", 0.9, "header")
    result = DetectionAggregator.aggregate([d1, d2])
    assert result[0].confidence >= result[1].confidence
