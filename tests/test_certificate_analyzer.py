"""Tests for certificate analyzer."""
import pytest
from analyzers.certificate import CertificateAnalyzer
from models.technology import Technology, EvidenceRule
from core.context import ScanContext


@pytest.fixture
def certificate_rules():
    """Technology rules for certificate detection."""
    return [
        Technology(
            name="AWS",
            category="Cloud Platform",
            evidence_rules=[
                EvidenceRule(type="certificate_issuer", pattern="Amazon", confidence=0.9),
                EvidenceRule(type="certificate_cn", pattern="amazonaws\\.com", confidence=0.95),
            ],
        ),
        Technology(
            name="Cloudflare",
            category="CDN",
            evidence_rules=[
                EvidenceRule(type="certificate_cn", pattern="cloudflare\\.com", confidence=0.95),
            ],
        ),
        Technology(
            name="Let's Encrypt",
            category="SSL/TLS Provider",
            evidence_rules=[
                EvidenceRule(type="certificate_issuer", pattern="Let's Encrypt", confidence=0.95),
            ],
        ),
    ]


@pytest.fixture
def mock_context_with_tls():
    """Mock scan context with TLS data."""
    return ScanContext(
        url="https://example.com",
        html="<html></html>",
        headers={},
        cookies={},
        scripts=[],
        stylesheets=[],
        js_globals=set(),
        dns_records={},
        tls={
            "issuer": "Amazon Security Certificate Authority",
            "cn": "example.amazonaws.com",
            "san": ["example.amazonaws.com", "*.example.amazonaws.com"],
        },
        status_code=200,
    )


@pytest.fixture
def mock_context_with_cloudflare():
    """Mock context with Cloudflare certificate."""
    return ScanContext(
        url="https://example.com",
        html="<html></html>",
        headers={},
        cookies={},
        scripts=[],
        stylesheets=[],
        js_globals=set(),
        dns_records={},
        tls={
            "issuer": "Cloudflare Inc.",
            "cn": "example.cloudflare.com",
            "san": ["example.cloudflare.com", "*.cloudflare.com"],
        },
        status_code=200,
    )


@pytest.fixture
def mock_context_without_tls():
    """Mock scan context without TLS data."""
    return ScanContext(
        url="https://example.com",
        html="<html></html>",
        headers={},
        cookies={},
        scripts=[],
        stylesheets=[],
        js_globals=set(),
        dns_records={},
        tls=None,
        status_code=200,
    )


@pytest.mark.asyncio
async def test_certificate_analyzer_detects_aws(certificate_rules, mock_context_with_tls):
    """Test certificate analyzer detects AWS from certificate issuer."""
    analyzer = CertificateAnalyzer(certificate_rules)
    
    detections = await analyzer.analyze(mock_context_with_tls)
    
    # Should detect AWS from both issuer and CN
    assert len(detections) >= 1
    aws_detections = [d for d in detections if d.name == "AWS"]
    assert len(aws_detections) >= 1
    
    # Check that both certificate_issuer and certificate_cn are detected
    evidence_types = {d.evidence.type for d in aws_detections}
    assert "certificate_issuer" in evidence_types or "certificate_cn" in evidence_types


@pytest.mark.asyncio
async def test_certificate_analyzer_detects_cloudflare(certificate_rules, mock_context_with_cloudflare):
    """Test certificate analyzer detects Cloudflare from CN."""
    analyzer = CertificateAnalyzer(certificate_rules)
    
    detections = await analyzer.analyze(mock_context_with_cloudflare)
    
    # Should detect Cloudflare
    assert len(detections) >= 1
    cloudflare_detections = [d for d in detections if d.name == "Cloudflare"]
    assert len(cloudflare_detections) >= 1
    assert cloudflare_detections[0].evidence.type == "certificate_cn"


@pytest.mark.asyncio
async def test_certificate_analyzer_no_tls(certificate_rules, mock_context_without_tls):
    """Test certificate analyzer handles missing TLS data gracefully."""
    analyzer = CertificateAnalyzer(certificate_rules)
    
    detections = await analyzer.analyze(mock_context_without_tls)
    
    # Should return empty list when no TLS data
    assert detections == []


@pytest.mark.asyncio
async def test_certificate_analyzer_confidence_levels(certificate_rules, mock_context_with_tls):
    """Test certificate analyzer correctly assigns confidence levels."""
    analyzer = CertificateAnalyzer(certificate_rules)
    
    detections = await analyzer.analyze(mock_context_with_tls)
    
    # All detections should have confidence values
    for detection in detections:
        assert isinstance(detection.confidence, float)
        assert 0 <= detection.confidence <= 1.0
