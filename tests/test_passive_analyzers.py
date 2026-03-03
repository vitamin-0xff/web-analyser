import pytest
from core.context import ScanContext
from analyzers.script_content import ScriptContentAnalyzer
from analyzers.favicon import FaviconAnalyzer
from analyzers.forms import FormsAnalyzer
from analyzers.sri import SRIAnalyzer
from analyzers.comments import CommentsAnalyzer
from models.technology import Technology, EvidenceRule


@pytest.fixture
def sample_context():
    return ScanContext(
        url="https://example.com",
        headers={},
        html="""
        <html>
            <head>
                <script>
                    window.gtag('config', 'GA-123456');
                    var mixpanel = {init: function() {}};
                </script>
                <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.min.js" 
                        integrity="sha384-9ndCyUaIbzAi2FUVXJi0CjmCapSmO7SnpJef0486qhLnuZ2cdeRhO02iuK6FUUVM"></script>
                <link rel="stylesheet" href="style.css" 
                      integrity="sha384-test123">
                <style>
                    /* Bootstrap v5.3.0 */
                    body { margin: 0; }
                </style>
            </head>
            <body>
                <!-- WordPress Theme Name: Twenty Twenty-One -->
                <!-- Generator: WooCommerce 7.x -->
                <form action="/login" method="post">
                    <input type="hidden" name="csrfmiddlewaretoken" value="abc123">
                    <input type="text" name="username">
                </form>
                <form action="?wc-ajax=update_cart" method="post">
                    <input type="hidden" name="_wp_http_referer" value="/cart">
                </form>
            </body>
        </html>
        """,
        cookies={},
        scripts=["https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.min.js"],
        stylesheets=["style.css"],
        js_globals=set(),
        tls=None,
        dns_records={},
        favicon_hash="a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"  # Shopify hash from rules
    )


@pytest.mark.asyncio
async def test_script_content_analyzer(sample_context):
    rules = [
        Technology(
            name="Google Analytics",
            category="Analytics",
            evidence_rules=[
                EvidenceRule(type="script_content_pattern", value="gtag\\(", confidence=0.8),
                EvidenceRule(type="inline_js_variable", value="__gaTracker", confidence=0.8),
            ]
        ),
        Technology(
            name="Mixpanel",
            category="Analytics",
            evidence_rules=[
                EvidenceRule(type="inline_js_variable", value="mixpanel", confidence=0.7),
            ]
        )
    ]
    
    analyzer = ScriptContentAnalyzer(rules)
    detections = await analyzer.analyze(sample_context)
    
    assert len(detections) == 2
    names = {d.name for d in detections}
    assert "Google Analytics" in names
    assert "Mixpanel" in names


@pytest.mark.asyncio
async def test_favicon_analyzer(sample_context):
    rules = [
        Technology(
            name="Shopify",
            category="Ecommerce",
            evidence_rules=[
                EvidenceRule(type="favicon_hash", value="a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", confidence=0.7),
            ]
        ),
        Technology(
            name="WordPress",
            category="CMS",
            evidence_rules=[
                EvidenceRule(type="favicon_hash", value="different_hash", confidence=0.7),
            ]
        )
    ]
    
    analyzer = FaviconAnalyzer(rules)
    detections = await analyzer.analyze(sample_context)
    
    assert len(detections) == 1
    assert detections[0].name == "Shopify"
    assert detections[0].confidence == 0.7


@pytest.mark.asyncio
async def test_forms_analyzer(sample_context):
    rules = [
        Technology(
            name="Django",
            category="Backend Framework",
            evidence_rules=[
                EvidenceRule(type="hidden_field_name", value="csrfmiddlewaretoken", confidence=0.9),
            ]
        ),
        Technology(
            name="WooCommerce",
            category="Ecommerce",
            evidence_rules=[
                EvidenceRule(type="hidden_field_name", value="_wp_http_referer", confidence=0.6),
                EvidenceRule(type="form_action_pattern", value="\\?wc-ajax=", confidence=0.7),
            ]
        )
    ]
    
    analyzer = FormsAnalyzer(rules)
    detections = await analyzer.analyze(sample_context)
    
    assert len(detections) == 2
    names = {d.name for d in detections}
    assert "Django" in names
    assert "WooCommerce" in names


@pytest.mark.asyncio
async def test_sri_analyzer(sample_context):
    rules = [
        Technology(
            name="Bootstrap",
            category="Frontend Framework",
            version="5.3.0",
            evidence_rules=[
                EvidenceRule(
                    type="sri_hash", 
                    value="sha384-9ndCyUaIbzAi2FUVXJi0CjmCapSmO7SnpJef0486qhLnuZ2cdeRhO02iuK6FUUVM", 
                    confidence=0.95
                ),
            ]
        ),
        Technology(
            name="jQuery",
            category="JavaScript Library",
            version="3.7.1",
            evidence_rules=[
                EvidenceRule(
                    type="sri_hash", 
                    value="sha256-different_hash", 
                    confidence=0.95
                ),
            ]
        )
    ]
    
    analyzer = SRIAnalyzer(rules)
    detections = await analyzer.analyze(sample_context)
    
    assert len(detections) == 1
    assert detections[0].name == "Bootstrap"
    assert detections[0].version == "5.3.0"
    assert detections[0].confidence == 0.95


@pytest.mark.asyncio
async def test_comments_analyzer(sample_context):
    rules = [
        Technology(
            name="WordPress",
            category="CMS",
            evidence_rules=[
                EvidenceRule(type="html_comment", value="WordPress|Theme Name:", confidence=0.7),
            ]
        ),
        Technology(
            name="WooCommerce",
            category="Ecommerce",
            evidence_rules=[
                EvidenceRule(type="html_comment", value="WooCommerce", confidence=0.6),
            ]
        ),
        Technology(
            name="Bootstrap",
            category="Frontend Framework",
            evidence_rules=[
                EvidenceRule(type="css_comment", value="Bootstrap v", confidence=0.6),
            ]
        )
    ]
    
    analyzer = CommentsAnalyzer(rules)
    detections = await analyzer.analyze(sample_context)
    
    assert len(detections) == 3
    names = {d.name for d in detections}
    assert "WordPress" in names
    assert "WooCommerce" in names
    assert "Bootstrap" in names


@pytest.mark.asyncio
async def test_no_favicon_hash():
    """Test when no favicon hash is available"""
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
        favicon_hash=None
    )
    
    rules = [
        Technology(
            name="Shopify",
            category="Ecommerce",
            evidence_rules=[
                EvidenceRule(type="favicon_hash", value="some_hash", confidence=0.7),
            ]
        )
    ]
    
    analyzer = FaviconAnalyzer(rules)
    detections = await analyzer.analyze(context)
    
    assert len(detections) == 0


@pytest.mark.asyncio
async def test_no_forms():
    """Test when no forms are present"""
    context = ScanContext(
        url="https://example.com",
        headers={},
        html="<html><body>No forms here</body></html>",
        cookies={},
        scripts=[],
        stylesheets=[],
        js_globals=set(),
        tls=None,
        dns_records={}
    )
    
    rules = [
        Technology(
            name="Django",
            category="Backend Framework",
            evidence_rules=[
                EvidenceRule(type="hidden_field_name", value="csrfmiddlewaretoken", confidence=0.9),
            ]
        )
    ]
    
    analyzer = FormsAnalyzer(rules)
    detections = await analyzer.analyze(context)
    
    assert len(detections) == 0
