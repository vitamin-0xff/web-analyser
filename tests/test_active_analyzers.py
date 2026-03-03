"""Tests for active detection analyzers (GraphQL, API probing, Error triggering)."""
import pytest
from unittest.mock import AsyncMock, patch
from analyzers.graphql import GraphQLAnalyzer
from analyzers.api_probe import APIProbeAnalyzer
from analyzers.error_probe import ErrorProbeAnalyzer
from models.technology import Technology, EvidenceRule
from core.context import ScanContext
import httpx


@pytest.fixture
def graphql_rules():
    return [
        Technology(
            name="Apollo GraphQL",
            category="GraphQL Server",
            evidence_rules=[
                EvidenceRule(type="graphql_introspection", pattern="apollo", confidence=0.9),
                EvidenceRule(type="graphql_header", name="X-Apollo-Tracing", pattern=".*", confidence=1.0),
            ],
        ),
        Technology(
            name="Hasura",
            category="GraphQL Server",
            evidence_rules=[
                EvidenceRule(type="graphql_introspection", pattern="hasura", confidence=0.95),
            ],
        ),
    ]


@pytest.fixture
def api_rules():
    return [
        Technology(
            name="FastAPI",
            category="Web Framework",
            evidence_rules=[
                EvidenceRule(type="api_response", pattern="FastAPI", confidence=0.9),
                EvidenceRule(type="api_header", name="Server", pattern="uvicorn", confidence=0.5),
            ],
        ),
        Technology(
            name="Django REST Framework",
            category="Web Framework",
            evidence_rules=[
                EvidenceRule(type="api_response", pattern="django|DRF", confidence=0.7),
            ],
        ),
    ]


@pytest.fixture
def error_rules():
    return [
        Technology(
            name="Flask",
            category="Web Framework",
            evidence_rules=[
                EvidenceRule(type="error_message", pattern="flask\\.|werkzeug\\.", confidence=0.9),
            ],
        ),
        Technology(
            name="PostgreSQL",
            category="Database",
            evidence_rules=[
                EvidenceRule(type="error_message", pattern="PostgreSQL|psycopg2", confidence=0.9),
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
async def test_graphql_analyzer_detects_apollo(graphql_rules, mock_context):
    """Test GraphQL analyzer detects Apollo GraphQL server."""
    analyzer = GraphQLAnalyzer(graphql_rules)
    
    # Mock the fetch_url to return a GraphQL response
    with patch('analyzers.graphql.fetch_url') as mock_fetch:
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.text = '{"data": {"__schema": {"queryType": {"name": "Query"}}}, "extensions": {"apollo": "trace"}}'
        mock_response.headers = {"X-Apollo-Tracing": "enabled"}
        mock_fetch.return_value = mock_response
        
        detections = await analyzer.analyze(mock_context)
        
        # Should detect Apollo from both introspection and header
        assert len(detections) >= 1
        assert any(d.name == "Apollo GraphQL" for d in detections)
        apollo_detections = [d for d in detections if d.name == "Apollo GraphQL"]
        assert any(d.evidence.type == "graphql_introspection" for d in apollo_detections) or \
               any(d.evidence.type == "graphql_header" for d in apollo_detections)


@pytest.mark.asyncio
async def test_graphql_analyzer_no_endpoint(graphql_rules, mock_context):
    """Test GraphQL analyzer handles missing GraphQL endpoints."""
    analyzer = GraphQLAnalyzer(graphql_rules)
    
    # Mock the fetch_url to return 404
    with patch('analyzers.graphql.fetch_url') as mock_fetch:
        mock_response = AsyncMock()
        mock_response.status_code = 404
        mock_response.text = "Not Found"
        mock_response.headers = {}
        mock_fetch.return_value = mock_response
        
        detections = await analyzer.analyze(mock_context)
        
        # Should not detect anything
        assert len(detections) == 0


@pytest.mark.asyncio
async def test_api_probe_detects_fastapi(api_rules, mock_context):
    """Test API probe analyzer detects FastAPI."""
    analyzer = APIProbeAnalyzer(api_rules)
    
    # Mock the fetch_url to return a FastAPI response
    with patch('analyzers.api_probe.fetch_url') as mock_fetch:
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.text = '{"detail": "Not Found", "docs": "/docs", "openapi": "/openapi.json"}'
        mock_response.headers = {"server": "uvicorn", "content-type": "application/json"}
        mock_fetch.return_value = mock_response
        
        detections = await analyzer.analyze(mock_context)
        
        # Should detect FastAPI
        assert len(detections) >= 1
        assert any(d.name == "FastAPI" for d in detections)


@pytest.mark.asyncio
async def test_api_probe_handles_errors(api_rules, mock_context):
    """Test API probe analyzer handles connection errors gracefully."""
    analyzer = APIProbeAnalyzer(api_rules)
    
    # Mock the fetch_url to raise an exception
    with patch('analyzers.api_probe.fetch_url') as mock_fetch:
        mock_fetch.side_effect = httpx.ConnectError("Connection refused")
        
        detections = await analyzer.analyze(mock_context)
        
        # Should not crash, return empty list
        assert isinstance(detections, list)
        assert len(detections) == 0


@pytest.mark.asyncio
async def test_error_probe_detects_flask(error_rules, mock_context):
    """Test error probe analyzer detects Flask from error messages."""
    analyzer = ErrorProbeAnalyzer(error_rules)
    
    # Mock the fetch_url to return a Flask error
    with patch('analyzers.error_probe.fetch_url') as mock_fetch:
        mock_response = AsyncMock()
        mock_response.status_code = 500
        mock_response.text = '''
        <html>
        <head><title>Internal Server Error</title></head>
        <body>
        <h1>500 Internal Server Error</h1>
        <p>Traceback (most recent call last):
          File "/app/flask/app.py", line 2309, in __call__
            return self.wsgi_app(environ, start_response)
          werkzeug.exceptions.InternalServerError: 500 Internal Server Error
        </p>
        </body>
        </html>
        '''
        mock_response.headers = {"server": "Werkzeug/2.0.1 Python/3.9.5"}
        mock_fetch.return_value = mock_response
        
        detections = await analyzer.analyze(mock_context)
        
        # Should detect Flask
        assert len(detections) >= 1
        assert any(d.name == "Flask" for d in detections)
        flask_detection = next(d for d in detections if d.name == "Flask")
        assert flask_detection.evidence.type == "error_message"
        assert "flask" in flask_detection.evidence.value.lower() or "werkzeug" in flask_detection.evidence.value.lower()


@pytest.mark.asyncio
async def test_error_probe_detects_postgresql(error_rules, mock_context):
    """Test error probe analyzer detects PostgreSQL from error messages."""
    analyzer = ErrorProbeAnalyzer(error_rules)
    
    # Mock the fetch_url to return a database error
    with patch('analyzers.error_probe.fetch_url') as mock_fetch:
        mock_response = AsyncMock()
        mock_response.status_code = 500
        mock_response.text = '''
        DatabaseError: relation "users" does not exist
        LINE 1: SELECT * FROM users WHERE id = 1
        
        psycopg2.errors.UndefinedTable: relation "users" does not exist
        '''
        mock_response.headers = {}
        mock_fetch.return_value = mock_response
        
        detections = await analyzer.analyze(mock_context)
        
        # Should detect PostgreSQL
        assert len(detections) >= 1
        assert any(d.name == "PostgreSQL" for d in detections)


@pytest.mark.asyncio
async def test_error_probe_no_errors(error_rules, mock_context):
    """Test error probe analyzer handles successful responses."""
    analyzer = ErrorProbeAnalyzer(error_rules)
    
    # Mock the fetch_url to return success responses
    with patch('analyzers.error_probe.fetch_url') as mock_fetch:
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.text = "OK"
        mock_response.headers = {}
        mock_fetch.return_value = mock_response
        
        detections = await analyzer.analyze(mock_context)
        
        # Should not detect anything from successful responses
        assert len(detections) == 0
