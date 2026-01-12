"""Tests for API Key detection analyzer."""
import pytest
from unittest.mock import AsyncMock, patch
from analyzers.api_keys import APIKeyPassiveAnalyzer, APIKeyActiveAnalyzer
from models.technology import Technology, EvidenceRule
from core.context import ScanContext


@pytest.fixture
def api_key_rules():
    return [
        Technology(
            name="AWS Access Key",
            category="Cloud Credentials",
            evidence_rules=[
                EvidenceRule(type="api_key_pattern", pattern=r'AKIA[0-9A-Z]{16}', confidence=0.95),
            ],
        ),
        Technology(
            name="Stripe API Key",
            category="Payment Credentials",
            evidence_rules=[
                EvidenceRule(type="api_key_pattern", pattern=r'sk_(live|test)_[0-9a-zA-Z]{20,}', confidence=0.95),
            ],
        ),
        Technology(
            name="GitHub Token",
            category="VCS Credentials",
            evidence_rules=[
                EvidenceRule(type="api_key_pattern", pattern=r'ghp_[0-9a-zA-Z]{36}', confidence=0.95),
            ],
        ),
        Technology(
            name="RSA Private Key",
            category="Cryptographic Keys",
            evidence_rules=[
                EvidenceRule(type="private_key", pattern=r'-----BEGIN RSA PRIVATE KEY-----[\s\S]+?-----END RSA PRIVATE KEY-----', confidence=1.0),
            ],
        ),
        Technology(
            name="MongoDB Connection String",
            category="Database Credentials",
            evidence_rules=[
                EvidenceRule(type="connection_string", pattern=r'mongodb(\+srv)?://[^:]*:[^@]*@[^\s"]+', confidence=0.9),
            ],
        ),
    ]


@pytest.fixture
def mock_context():
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
async def test_detects_aws_access_key(api_key_rules, mock_context):
    """Test detection of AWS Access Key format in passive analyzer."""
    analyzer = APIKeyPassiveAnalyzer(api_key_rules)
    
    # Modify context with AWS key
    modified_context = ScanContext(
        url=mock_context.url,
        html="<html><body>API_KEY=AKIAIOSFODNN7EXAMPLE</body></html>",
        headers=mock_context.headers,
        cookies=mock_context.cookies,
        scripts=mock_context.scripts,
        stylesheets=mock_context.stylesheets,
        js_globals=mock_context.js_globals,
        dns_records=mock_context.dns_records,
        tls=mock_context.tls,
        status_code=mock_context.status_code,
    )
    
    with patch('analyzers.api_keys.fetch_url') as mock_fetch:
        mock_response = AsyncMock()
        mock_response.status_code = 404
        mock_response.text = ""
        mock_fetch.return_value = mock_response
        
        detections = await analyzer.analyze(modified_context)
        
        # Should detect AWS key
        assert len(detections) >= 1
        assert any(d.name == "AWS Access Key" for d in detections)
        # Key should be masked
        aws_detection = next(d for d in detections if d.name == "AWS Access Key")
        assert aws_detection.evidence.value.startswith("*")


@pytest.mark.asyncio
async def test_detects_stripe_api_key(api_key_rules, mock_context):
    """Test detection of Stripe API Key format in passive analyzer."""
    analyzer = APIKeyPassiveAnalyzer(api_key_rules)
    
    modified_context = ScanContext(
        url=mock_context.url,
        html="<html><body>stripe_key=sk_live_51234567890abcdefghijklmno</body></html>",
        headers=mock_context.headers,
        cookies=mock_context.cookies,
        scripts=mock_context.scripts,
        stylesheets=mock_context.stylesheets,
        js_globals=mock_context.js_globals,
        dns_records=mock_context.dns_records,
        tls=mock_context.tls,
        status_code=mock_context.status_code,
    )
    
    with patch('analyzers.api_keys.fetch_url') as mock_fetch:
        mock_response = AsyncMock()
        mock_response.status_code = 404
        mock_response.text = ""
        mock_fetch.return_value = mock_response
        
        detections = await analyzer.analyze(modified_context)
        
        # Should detect Stripe key
        assert len(detections) >= 1
        assert any(d.name == "Stripe API Key" for d in detections)


@pytest.mark.asyncio
async def test_detects_github_token(api_key_rules, mock_context):
    """Test detection of GitHub Personal Access Token in passive analyzer."""
    analyzer = APIKeyPassiveAnalyzer(api_key_rules)

    # ghp_ followed by exactly 36 alphanumeric characters
    modified_context = ScanContext(
        url=mock_context.url,
        html="<html><body>token=ghp_1234567890abcdefghijklmnopqrstuvwxyzabcd</body></html>",
        headers=mock_context.headers,
        cookies=mock_context.cookies,
        scripts=mock_context.scripts,
        stylesheets=mock_context.stylesheets,
        js_globals=mock_context.js_globals,
        dns_records=mock_context.dns_records,
        tls=mock_context.tls,
        status_code=mock_context.status_code,
    )

    with patch('analyzers.api_keys.fetch_url') as mock_fetch:
        mock_response = AsyncMock()
        mock_response.status_code = 404
        mock_response.text = ""
        mock_fetch.return_value = mock_response

        detections = await analyzer.analyze(modified_context)

        # Should detect GitHub token (ghp_ pattern requires 36 chars after prefix)
        assert len(detections) >= 1
        assert any(d.name == "GitHub Token" for d in detections)


@pytest.mark.asyncio
async def test_detects_rsa_private_key(api_key_rules, mock_context):
    """Test detection of RSA Private Key in passive analyzer."""
    analyzer = APIKeyPassiveAnalyzer(api_key_rules)
    
    private_key_content = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA2Z3qX2BTLS39R3wvUL3c5pGL...
...
-----END RSA PRIVATE KEY-----"""
    
    modified_context = ScanContext(
        url=mock_context.url,
        html=f"<html><body>{private_key_content}</body></html>",
        headers=mock_context.headers,
        cookies=mock_context.cookies,
        scripts=mock_context.scripts,
        stylesheets=mock_context.stylesheets,
        js_globals=mock_context.js_globals,
        dns_records=mock_context.dns_records,
        tls=mock_context.tls,
        status_code=mock_context.status_code,
    )
    
    with patch('analyzers.api_keys.fetch_url') as mock_fetch:
        mock_response = AsyncMock()
        mock_response.status_code = 404
        mock_response.text = ""
        mock_fetch.return_value = mock_response
        
        detections = await analyzer.analyze(modified_context)
        
        # Should detect RSA private key
        assert len(detections) >= 1
        assert any(d.name == "RSA Private Key" for d in detections)
        # Sensitive key should be masked
        rsa_detection = next(d for d in detections if d.name == "RSA Private Key")
        assert "MASKED" in rsa_detection.evidence.value


@pytest.mark.asyncio
async def test_detects_mongodb_connection_string(api_key_rules, mock_context):
    """Test detection of MongoDB Connection String in passive analyzer."""
    analyzer = APIKeyPassiveAnalyzer(api_key_rules)
    
    modified_context = ScanContext(
        url=mock_context.url,
        html="<html><body>db_url=mongodb://user:password123@cluster.mongodb.net/database</body></html>",
        headers=mock_context.headers,
        cookies=mock_context.cookies,
        scripts=mock_context.scripts,
        stylesheets=mock_context.stylesheets,
        js_globals=mock_context.js_globals,
        dns_records=mock_context.dns_records,
        tls=mock_context.tls,
        status_code=mock_context.status_code,
    )
    
    with patch('analyzers.api_keys.fetch_url') as mock_fetch:
        mock_response = AsyncMock()
        mock_response.status_code = 404
        mock_response.text = ""
        mock_fetch.return_value = mock_response
        
        detections = await analyzer.analyze(modified_context)
        
        # Should detect MongoDB connection string
        assert len(detections) >= 1
        assert any(d.name == "MongoDB Connection String" for d in detections)
        # Password should be masked
        mongo_detection = next(d for d in detections if d.name == "MongoDB Connection String")
        assert "*" in mongo_detection.evidence.value


@pytest.mark.asyncio
async def test_no_keys_in_clean_response(api_key_rules, mock_context):
    """Test that analyzer doesn't produce false positives."""
    analyzer = APIKeyPassiveAnalyzer(api_key_rules)
    
    modified_context = ScanContext(
        url=mock_context.url,
        html="<html><body>Just a normal page with no credentials</body></html>",
        headers=mock_context.headers,
        cookies=mock_context.cookies,
        scripts=mock_context.scripts,
        stylesheets=mock_context.stylesheets,
        js_globals=mock_context.js_globals,
        dns_records=mock_context.dns_records,
        tls=mock_context.tls,
        status_code=mock_context.status_code,
    )
    
    with patch('analyzers.api_keys.fetch_url') as mock_fetch:
        mock_response = AsyncMock()
        mock_response.status_code = 404
        mock_response.text = ""
        mock_fetch.return_value = mock_response
        
        detections = await analyzer.analyze(modified_context)
        
        # Should not detect anything
        assert len(detections) == 0


@pytest.mark.asyncio
async def test_handles_fetch_errors_gracefully(api_key_rules, mock_context):
    """Test that passive analyzer handles errors gracefully."""
    analyzer = APIKeyPassiveAnalyzer(api_key_rules)
    
    with patch('analyzers.api_keys.fetch_url') as mock_fetch:
        mock_fetch.side_effect = Exception("Connection refused")
        
        detections = await analyzer.analyze(mock_context)
        
        # Should return list (might be empty or have main page results)
        assert isinstance(detections, list)


# Tests for Active API Key Analyzer
@pytest.mark.asyncio
async def test_active_analyzer_probes_endpoints(api_key_rules, mock_context):
    """Test that active analyzer makes HTTP requests to endpoints."""
    analyzer = APIKeyActiveAnalyzer(api_key_rules)
    
    with patch('analyzers.api_keys.fetch_url') as mock_fetch:
        # Simulate finding an exposed env file
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        mock_fetch.return_value = mock_response
        
        detections = await analyzer.analyze(mock_context)
        
        # Should have made HTTP requests
        assert mock_fetch.called
        # Should detect exposed credentials
        assert len(detections) >= 1


@pytest.mark.asyncio
async def test_active_analyzer_handles_404_responses(api_key_rules, mock_context):
    """Test that active analyzer continues even when endpoints return 404."""
    analyzer = APIKeyActiveAnalyzer(api_key_rules)
    
    with patch('analyzers.api_keys.fetch_url') as mock_fetch:
        mock_response = AsyncMock()
        mock_response.status_code = 404
        mock_response.text = ""
        mock_fetch.return_value = mock_response
        
        detections = await analyzer.analyze(mock_context)
        
        # Should have made HTTP requests despite 404
        assert mock_fetch.called
        # No credentials exposed in 404 responses
        assert len(detections) == 0
