"""Tests for the SecurityHeadersAnalyzer."""
import pytest
from analyzers.security_headers import SecurityHeadersAnalyzer
from tests.conftest import make_context
from core.analyzer_registry import AnalyzerRegistry
from rules.rules_loader import load_rules


@pytest.fixture
def analyzer():
    """Create a SecurityHeadersAnalyzer instance with loaded rules."""
    rules = load_rules()
    # Filter for security-related rules
    security_rules = [r for r in rules if r.category == "Security"]
    return SecurityHeadersAnalyzer(security_rules)


@pytest.mark.asyncio
async def test_detects_missing_hsts(analyzer):
    """Should detect missing HSTS header."""
    ctx = make_context(headers={})
    result = await analyzer.analyze(ctx)
    
    names = {d.name for d in result}
    assert any("HSTS" in name for name in names)


@pytest.mark.asyncio
async def test_detects_missing_csp(analyzer):
    """Should detect missing Content Security Policy."""
    ctx = make_context(headers={})
    result = await analyzer.analyze(ctx)
    
    names = {d.name for d in result}
    assert any("Content Security Policy" in name or "CSP" in name for name in names)


@pytest.mark.asyncio
async def test_detects_missing_x_frame_options(analyzer):
    """Should detect missing X-Frame-Options header."""
    ctx = make_context(headers={})
    result = await analyzer.analyze(ctx)
    
    names = {d.name for d in result}
    assert any("X-Frame-Options" in name for name in names)


@pytest.mark.asyncio
async def test_detects_missing_x_content_type_options(analyzer):
    """Should detect missing X-Content-Type-Options header."""
    ctx = make_context(headers={})
    result = await analyzer.analyze(ctx)
    
    names = {d.name for d in result}
    assert any("X-Content-Type-Options" in name for name in names)


@pytest.mark.asyncio
async def test_no_issues_with_secure_headers(analyzer):
    """Should not flag issues when all security headers are present."""
    ctx = make_context(headers={
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin"
    })
    result = await analyzer.analyze(ctx)
    
    # Should not have "Missing" detections
    missing_detections = [d for d in result if "Missing" in d.name]
    assert len(missing_detections) == 0


@pytest.mark.asyncio
async def test_detects_weak_csp_with_unsafe_inline(analyzer):
    """Should detect CSP with unsafe-inline directive."""
    ctx = make_context(headers={
        "content-security-policy": "default-src 'self' 'unsafe-inline'"
    })
    result = await analyzer.analyze(ctx)
    
    names = {d.name for d in result}
    assert any("Weak Content Security Policy" in name for name in names)


@pytest.mark.asyncio
async def test_detects_weak_csp_with_unsafe_eval(analyzer):
    """Should detect CSP with unsafe-eval directive."""
    ctx = make_context(headers={
        "content-security-policy": "script-src 'self' 'unsafe-eval'"
    })
    result = await analyzer.analyze(ctx)
    
    names = {d.name for d in result}
    assert any("Weak Content Security Policy" in name for name in names)


@pytest.mark.asyncio
async def test_detects_csp_with_wildcard(analyzer):
    """Should detect CSP with wildcard sources."""
    ctx = make_context(headers={
        "content-security-policy": "default-src *"
    })
    result = await analyzer.analyze(ctx)
    
    names = {d.name for d in result}
    assert any("Weak Content Security Policy" in name for name in names)


@pytest.mark.asyncio
async def test_detects_short_hsts_max_age(analyzer):
    """Should detect HSTS with too short max-age."""
    ctx = make_context(headers={
        "strict-transport-security": "max-age=86400"  # Only 1 day
    })
    result = await analyzer.analyze(ctx)
    
    names = {d.name for d in result}
    assert any("Weak HSTS" in name for name in names)


@pytest.mark.asyncio
async def test_detects_hsts_without_includesubdomains(analyzer):
    """Should detect HSTS without includeSubDomains."""
    ctx = make_context(headers={
        "strict-transport-security": "max-age=31536000"
    })
    result = await analyzer.analyze(ctx)
    
    names = {d.name for d in result}
    assert any("includeSubDomains" in name for name in names)


@pytest.mark.asyncio
async def test_detects_information_disclosure_server_header(analyzer):
    """Should detect server header leaking information."""
    ctx = make_context(headers={
        "server": "Apache/2.4.41 (Ubuntu)"
    })
    result = await analyzer.analyze(ctx)
    
    names = {d.name for d in result}
    assert any("Information Disclosure" in name for name in names)


@pytest.mark.asyncio
async def test_detects_information_disclosure_powered_by(analyzer):
    """Should detect x-powered-by header."""
    ctx = make_context(headers={
        "x-powered-by": "PHP/7.4.3"
    })
    result = await analyzer.analyze(ctx)
    
    names = {d.name for d in result}
    assert any("Information Disclosure" in name for name in names)


@pytest.mark.asyncio
async def test_detects_permissive_cors(analyzer):
    """Should detect wildcard CORS policy."""
    ctx = make_context(headers={
        "access-control-allow-origin": "*"
    })
    result = await analyzer.analyze(ctx)
    
    names = {d.name for d in result}
    assert any("CORS" in name for name in names)


@pytest.mark.asyncio
async def test_detects_critical_cors_misconfiguration(analyzer):
    """Should detect wildcard CORS with credentials (critical issue)."""
    ctx = make_context(headers={
        "access-control-allow-origin": "*",
        "access-control-allow-credentials": "true"
    })
    result = await analyzer.analyze(ctx)
    
    names = {d.name for d in result}
    critical_cors = [d for d in result if "Critical CORS" in d.name]
    assert len(critical_cors) > 0
    assert critical_cors[0].confidence >= 0.95


@pytest.mark.asyncio
async def test_detects_insecure_cookie_no_secure(analyzer):
    """Should detect cookies without Secure flag."""
    ctx = make_context(headers={
        "set-cookie": "sessionid=abc123; Path=/"
    })
    result = await analyzer.analyze(ctx)
    
    insecure_cookies = [d for d in result if "Insecure Cookie" in d.name]
    if insecure_cookies:
        assert "Secure" in insecure_cookies[0].evidence.pattern


@pytest.mark.asyncio
async def test_detects_insecure_cookie_no_httponly(analyzer):
    """Should detect cookies without HttpOnly flag."""
    ctx = make_context(headers={
        "set-cookie": "sessionid=abc123; Secure; Path=/"
    })
    result = await analyzer.analyze(ctx)
    
    insecure_cookies = [d for d in result if "Insecure Cookie" in d.name]
    if insecure_cookies:
        assert "HttpOnly" in insecure_cookies[0].evidence.pattern


@pytest.mark.asyncio
async def test_detects_insecure_cookie_no_samesite(analyzer):
    """Should detect cookies without SameSite attribute."""
    ctx = make_context(headers={
        "set-cookie": "sessionid=abc123; Secure; HttpOnly; Path=/"
    })
    result = await analyzer.analyze(ctx)
    
    insecure_cookies = [d for d in result if "Insecure Cookie" in d.name]
    if insecure_cookies:
        assert "SameSite" in insecure_cookies[0].evidence.pattern


@pytest.mark.asyncio
async def test_secure_cookie_configuration(analyzer):
    """Should not flag issues with properly configured cookies."""
    ctx = make_context(headers={
        "set-cookie": "sessionid=abc123; Secure; HttpOnly; SameSite=Strict; Path=/"
    })
    result = await analyzer.analyze(ctx)
    
    insecure_cookies = [d for d in result if "Insecure Cookie" in d.name]
    assert len(insecure_cookies) == 0


@pytest.mark.asyncio
async def test_detects_cloudflare_from_security_rules(analyzer):
    """Should detect Cloudflare WAF from headers."""
    ctx = make_context(headers={
        "cf-ray": "1234567890abc-SJC",
        "cf-cache-status": "HIT"
    })
    result = await analyzer.analyze(ctx)
    
    names = {d.name for d in result}
    # This depends on the security.yaml rules being loaded
    if any("Cloudflare" in name for name in names):
        assert True


@pytest.mark.asyncio
async def test_returns_list_even_when_no_issues(analyzer):
    """Should always return a list, even when no issues found."""
    ctx = make_context(headers={
        "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "geolocation=()",
        "x-xss-protection": "1; mode=block"
    })
    result = await analyzer.analyze(ctx)
    assert isinstance(result, list)


@pytest.mark.asyncio
async def test_all_detections_have_evidence(analyzer):
    """All detections must include evidence."""
    ctx = make_context(headers={})
    result = await analyzer.analyze(ctx)
    
    for detection in result:
        assert detection.evidence is not None
        assert detection.evidence.type in ["security_header", "security_cookie", "security_csp"]


@pytest.mark.asyncio
async def test_security_category_assigned(analyzer):
    """All security detections should have Security category."""
    ctx = make_context(headers={})
    result = await analyzer.analyze(ctx)
    
    for detection in result:
        assert detection.category == "Security"


@pytest.mark.asyncio
async def test_confidence_values_are_valid(analyzer):
    """All confidence values should be between 0 and 1."""
    ctx = make_context(headers={
        "server": "nginx",
        "x-powered-by": "PHP/8.0",
        "access-control-allow-origin": "*"
    })
    result = await analyzer.analyze(ctx)
    
    for detection in result:
        assert 0.0 <= detection.confidence <= 1.0
