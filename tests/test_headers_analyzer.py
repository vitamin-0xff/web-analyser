"""Tests for the HeadersAnalyzer."""
import pytest
import asyncio
from analyzers.headers import HeadersAnalyzer
from models.technology import Technology, EvidenceRule
from tests.conftest import make_context


def make_header_rule(tech_name: str, category: str, header_name: str, pattern: str, confidence: float = 0.8):
    return Technology(
        name=tech_name,
        category=category,
        evidence_rules=[
            EvidenceRule(type="header", name=header_name, pattern=pattern, confidence=confidence)
        ],
    )


@pytest.mark.asyncio
async def test_headers_analyzer_returns_list_on_match():
    """HeadersAnalyzer must return a list (not None) when a header matches."""
    rule = make_header_rule("Nginx", "Web Server", "server", r"nginx")
    analyzer = HeadersAnalyzer([rule])
    ctx = make_context(headers={"server": "nginx/1.24.0"})

    result = await analyzer.analyze(ctx)

    assert result is not None
    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0].name == "Nginx"


@pytest.mark.asyncio
async def test_headers_analyzer_returns_empty_list_on_no_match():
    """HeadersAnalyzer must return an empty list when no header matches."""
    rule = make_header_rule("Apache", "Web Server", "server", r"apache")
    analyzer = HeadersAnalyzer([rule])
    ctx = make_context(headers={"server": "nginx/1.24.0"})

    result = await analyzer.analyze(ctx)

    assert result == []


@pytest.mark.asyncio
async def test_headers_analyzer_pattern_case_insensitive():
    """Pattern match against header value should be case-insensitive."""
    rule = make_header_rule("PHP", "Language", "x-powered-by", r"php")
    analyzer = HeadersAnalyzer([rule])
    # Headers in ScanContext are always lowercase-keyed (normalised by the engine)
    ctx = make_context(headers={"x-powered-by": "PHP/8.1.0"})

    result = await analyzer.analyze(ctx)

    assert len(result) == 1
    assert result[0].name == "PHP"


@pytest.mark.asyncio
async def test_headers_analyzer_confidence_propagated():
    """Detection confidence should match the rule confidence."""
    rule = make_header_rule("Nginx", "Web Server", "server", r"nginx", confidence=0.9)
    analyzer = HeadersAnalyzer([rule])
    ctx = make_context(headers={"server": "nginx/1.24.0"})

    result = await analyzer.analyze(ctx)

    assert result[0].confidence == 0.9


@pytest.mark.asyncio
async def test_headers_analyzer_no_header_present():
    """No detection when the expected header is absent."""
    rule = make_header_rule("Nginx", "Web Server", "server", r"nginx")
    analyzer = HeadersAnalyzer([rule])
    ctx = make_context(headers={})

    result = await analyzer.analyze(ctx)

    assert result == []


@pytest.mark.asyncio
async def test_headers_analyzer_multiple_technologies():
    """Multiple matching technologies are all returned."""
    rules = [
        make_header_rule("Nginx", "Web Server", "server", r"nginx"),
        make_header_rule("PHP", "Language", "x-powered-by", r"php"),
    ]
    analyzer = HeadersAnalyzer(rules)
    ctx = make_context(headers={"server": "nginx/1.24", "x-powered-by": "PHP/8.0"})

    result = await analyzer.analyze(ctx)

    names = {d.name for d in result}
    assert "Nginx" in names
    assert "PHP" in names


@pytest.mark.asyncio
async def test_headers_analyzer_evidence_fields():
    """Evidence type, name, and value should be populated correctly."""
    rule = make_header_rule("Nginx", "Web Server", "server", r"nginx")
    analyzer = HeadersAnalyzer([rule])
    ctx = make_context(headers={"server": "nginx/1.24.0"})

    result = await analyzer.analyze(ctx)

    ev = result[0].evidence
    assert ev.type == "header"
    assert ev.name == "server"
    assert "nginx" in ev.value.lower()
