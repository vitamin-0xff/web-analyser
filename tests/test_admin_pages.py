"""Tests for admin pages analyzer."""
import pytest
from unittest.mock import AsyncMock, patch
from analyzers.admin_pages import AdminPagesAnalyzer
from models.technology import Technology, EvidenceRule
from core.context import ScanContext


@pytest.fixture
def admin_rules():
    """Technology rules for admin page detection."""
    return [
        Technology(
            name="WordPress",
            category="CMS",
            evidence_rules=[
                EvidenceRule(type="admin_page", pattern="wp-admin|wordpress", confidence=0.95),
                EvidenceRule(type="admin_interface", pattern="wp-content|wp-includes", confidence=0.9),
                EvidenceRule(type="header", name="X-Powered-By", pattern="wordpress", confidence=0.8),
            ],
        ),
        Technology(
            name="Django",
            category="Web Framework",
            evidence_rules=[
                EvidenceRule(type="admin_detection", pattern="django|Django", confidence=0.85),
                EvidenceRule(type="admin_page", pattern="Django administration|login", confidence=0.9),
            ],
        ),
        Technology(
            name="phpMyAdmin",
            category="Database Management",
            evidence_rules=[
                EvidenceRule(type="admin_interface", pattern="phpMyAdmin|phpmyadmin", confidence=0.95),
            ],
        ),
    ]


@pytest.fixture
def mock_context():
    """Mock scan context."""
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
async def test_admin_pages_detects_wordpress(admin_rules, mock_context):
    """Test admin pages analyzer detects WordPress admin panel."""
    analyzer = AdminPagesAnalyzer(admin_rules)
    
    # Mock the fetch_url to return a WordPress admin response
    with patch('analyzers.admin_pages.fetch_url') as mock_fetch:
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.text = '''
            <html>
                <title>wp-admin</title>
                <body>
                    <h1>WordPress Administration</h1>
                    <form>WordPress Login</form>
                </body>
            </html>
        '''
        mock_response.headers = {
            "X-Powered-By": "WordPress",
            "Content-Type": "text/html"
        }
        mock_fetch.return_value = mock_response
        
        detections = await analyzer.analyze(mock_context)
        
        # Should detect WordPress from admin page content
        assert len(detections) >= 1
        wordpress_detections = [d for d in detections if d.name == "WordPress"]
        assert len(wordpress_detections) >= 1
        assert any(d.evidence.type in ["admin_page", "header"] for d in wordpress_detections)


@pytest.mark.asyncio
async def test_admin_pages_detects_protected_admin(admin_rules, mock_context):
    """Test admin pages analyzer detects protected admin pages (403 status)."""
    analyzer = AdminPagesAnalyzer(admin_rules)
    
    # Mock the fetch_url to return a 403 response (protected admin)
    with patch('analyzers.admin_pages.fetch_url') as mock_fetch:
        mock_response = AsyncMock()
        mock_response.status_code = 403
        mock_response.text = 'Access Denied to Django administration'
        mock_response.headers = {"Content-Type": "text/html"}
        mock_fetch.return_value = mock_response
        
        detections = await analyzer.analyze(mock_context)
        
        # Should detect admin page from 403 status + content
        assert len(detections) >= 1
        django_detections = [d for d in detections if d.name == "Django"]
        assert len(django_detections) >= 1


@pytest.mark.asyncio
async def test_admin_pages_detects_phpmyadmin(admin_rules, mock_context):
    """Test admin pages analyzer detects phpMyAdmin."""
    analyzer = AdminPagesAnalyzer(admin_rules)
    
    # Mock the fetch_url to return phpMyAdmin response
    with patch('analyzers.admin_pages.fetch_url') as mock_fetch:
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.text = '''
            <html>
                <title>phpMyAdmin</title>
                <body>
                    <h1>phpMyAdmin 5.2.1</h1>
                    <form id="login">Database Login</form>
                </body>
            </html>
        '''
        mock_response.headers = {"Content-Type": "text/html"}
        mock_fetch.return_value = mock_response
        
        detections = await analyzer.analyze(mock_context)
        
        # Should detect phpMyAdmin from admin interface pattern
        assert len(detections) >= 1
        phpmyadmin_detections = [d for d in detections if d.name == "phpMyAdmin"]
        assert len(phpmyadmin_detections) >= 1


@pytest.mark.asyncio
async def test_admin_pages_no_admin_found(admin_rules, mock_context):
    """Test admin pages analyzer handles when no admin page is found."""
    analyzer = AdminPagesAnalyzer(admin_rules)
    
    # Mock the fetch_url to return regular page (not admin)
    with patch('analyzers.admin_pages.fetch_url') as mock_fetch:
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.text = '<html><body><h1>Welcome</h1><p>Regular page content</p></body></html>'
        mock_response.headers = {"Content-Type": "text/html"}
        mock_fetch.return_value = mock_response
        
        detections = await analyzer.analyze(mock_context)
        
        # Should not detect admin pages from regular content
        admin_detections = [d for d in detections if d.evidence.type in ["admin_page", "admin_interface", "admin_detection"]]
        assert len(admin_detections) == 0


@pytest.mark.asyncio
async def test_admin_pages_handles_timeout(admin_rules, mock_context):
    """Test admin pages analyzer handles network timeout gracefully."""
    analyzer = AdminPagesAnalyzer(admin_rules)
    
    # Mock the fetch_url to raise timeout exception
    with patch('analyzers.admin_pages.fetch_url') as mock_fetch:
        mock_fetch.side_effect = TimeoutError("Connection timeout")
        
        detections = await analyzer.analyze(mock_context)
        
        # Should handle gracefully and return empty list
        assert isinstance(detections, list)
