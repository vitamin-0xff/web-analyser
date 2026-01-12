import asyncio
from core.context import ScanContext
from analyzers.meta_tags import MetaTagsAnalyzer
from analyzers.structured_data import StructuredDataAnalyzer
from analyzers.pwa import PWAAnalyzer
from analyzers.robots_sitemap import RobotsSitemapAnalyzer
from analyzers.storage import StorageAnalyzer
from models.technology import Technology, EvidenceRule


def test_meta_tags_analyzer():
    """Test meta tag detection for CMS signatures."""
    html = '''
    <html>
    <head>
    <meta name="generator" content="Drupal 9">
    <meta property="og:type" content="website">
    </head>
    </html>
    '''
    
    techs = [
        Technology(
            name="Drupal",
            category="CMS",
            evidence_rules=[
                EvidenceRule(type="meta_name", name="generator", pattern="drupal", confidence=0.8)
            ]
        )
    ]
    
    context = ScanContext(
        url="https://example.com",
        headers={},
        html=html,
        cookies={},
        scripts=[],
        stylesheets=[],
        js_globals=set(),
        tls=None,
        dns_records={}
    )
    
    analyzer = MetaTagsAnalyzer(techs)
    detections = asyncio.run(analyzer.analyze(context))
    
    assert len(detections) == 1
    assert detections[0].name == "Drupal"
    assert detections[0].confidence == 0.8


def test_structured_data_analyzer():
    """Test JSON-LD pattern matching."""
    html = '''
    <html>
    <head>
    <script type="application/ld+json">
    {"@type": "Product", "@context": "https://schema.org"}
    </script>
    </head>
    </html>
    '''
    
    techs = [
        Technology(
            name="Ecommerce",
            category="Ecommerce",
            evidence_rules=[
                EvidenceRule(type="json_ld_pattern", pattern='"@type"\\s*:\\s*"Product"', confidence=0.5)
            ]
        )
    ]
    
    context = ScanContext(
        url="https://example.com",
        headers={},
        html=html,
        cookies={},
        scripts=[],
        stylesheets=[],
        js_globals=set(),
        tls=None,
        dns_records={}
    )
    
    analyzer = StructuredDataAnalyzer(techs)
    detections = asyncio.run(analyzer.analyze(context))
    
    assert len(detections) == 1
    assert detections[0].name == "Ecommerce"


def test_pwa_analyzer():
    """Test PWA manifest detection."""
    html = '<link rel="manifest" href="/manifest.json">'
    
    techs = [
        Technology(
            name="PWA",
            category="Architecture",
            evidence_rules=[
                EvidenceRule(type="pwa_manifest", pattern=".*", confidence=0.6)
            ]
        )
    ]
    
    context = ScanContext(
        url="https://example.com",
        headers={},
        html=html,
        cookies={},
        scripts=[],
        stylesheets=[],
        js_globals=set(),
        tls=None,
        dns_records={},
        manifest_url="https://example.com/manifest.json"
    )
    
    analyzer = PWAAnalyzer(techs)
    detections = asyncio.run(analyzer.analyze(context))
    
    assert len(detections) == 1
    assert detections[0].name == "PWA"


def test_robots_sitemap_analyzer():
    """Test robots.txt pattern matching."""
    robots_txt = "/wp-admin/\nDisallow: /wp-includes/"
    
    techs = [
        Technology(
            name="WordPress",
            category="CMS",
            evidence_rules=[
                EvidenceRule(type="robots_txt", pattern="/wp-admin/|/wp-includes/", confidence=0.8)
            ]
        )
    ]
    
    context = ScanContext(
        url="https://example.com",
        headers={},
        html="<html></html>",
        cookies={},
        scripts=[],
        stylesheets=[],
        js_globals=set(),
        tls=None,
        dns_records={},
        robots_txt=robots_txt
    )
    
    analyzer = RobotsSitemapAnalyzer(techs)
    detections = asyncio.run(analyzer.analyze(context))
    
    assert len(detections) == 1
    assert detections[0].name == "WordPress"


def test_storage_analyzer():
    """Test localStorage key pattern detection."""
    html = "localStorage.setItem('auth0_id', '...');"
    
    techs = [
        Technology(
            name="Auth0",
            category="Identity",
            evidence_rules=[
                EvidenceRule(type="js_storage_key", pattern="auth0", confidence=0.8)
            ]
        )
    ]
    
    context = ScanContext(
        url="https://example.com",
        headers={},
        html=html,
        cookies={},
        scripts=[],
        stylesheets=[],
        js_globals=set(),
        tls=None,
        dns_records={}
    )
    
    analyzer = StorageAnalyzer(techs)
    detections = asyncio.run(analyzer.analyze(context))
    
    assert len(detections) == 1
    assert detections[0].name == "Auth0"
