import pytest
from core.context import ScanContext
from analyzers.assets import AssetsAnalyzer
from models.technology import Technology, EvidenceRule


@pytest.fixture
def sample_context():
    return ScanContext(
        url="https://example.com",
        headers={
            "server": "Netlify",
            "x-nf-request-id": "12345"
        },
        html="""
        <html>
            <head>
                <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Roboto">
                <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
                <style>
                    @font-face {
                        font-family: 'CustomFont';
                        src: url('https://fonts.gstatic.com/s/roboto/v30/KFOmCnqEu92Fr1Mu4mxK.woff2');
                    }
                    body {
                        background-image: url('https://res.cloudinary.com/demo/image/upload/sample.jpg');
                    }
                </style>
            </head>
            <body>
                <img src="https://imagedelivery.net/abc123/def456.jpg">
                <iframe src="https://www.youtube.com/embed/dQw4w9WgXcQ"></iframe>
                <span class="material-icons">home</span>
            </body>
        </html>
        """,
        cookies={},
        scripts=[
            "https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.min.js",
            "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js"
        ],
        stylesheets=[
            "https://fonts.googleapis.com/css?family=Roboto",
            "https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css"
        ],
        js_globals=set(),
        tls=None,
        dns_records={}
    )


@pytest.mark.asyncio
async def test_assets_analyzer_fonts(sample_context):
    rules = [
        Technology(
            name="Google Fonts",
            category="Font Service",
            evidence_rules=[
                EvidenceRule(type="css_link", pattern="fonts\\.googleapis\\.com", confidence=0.8),
                EvidenceRule(type="font_src_pattern", pattern="fonts\\.gstatic\\.com", confidence=0.8),
            ]
        )
    ]
    
    analyzer = AssetsAnalyzer(rules)
    detections = await analyzer.analyze(sample_context)
    
    # Should detect both css_link and font_src_pattern
    assert len(detections) == 2
    assert all(d.name == "Google Fonts" for d in detections)
    assert detections[0].category == "Font Service"


@pytest.mark.asyncio
async def test_assets_analyzer_cdn(sample_context):
    rules = [
        Technology(
            name="jsDelivr",
            category="JavaScript CDN",
            evidence_rules=[
                EvidenceRule(type="script_src", pattern="cdn\\.jsdelivr\\.net", confidence=0.7),
            ]
        ),
        Technology(
            name="cdnjs",
            category="JavaScript CDN",
            evidence_rules=[
                EvidenceRule(type="script_src", pattern="cdnjs\\.cloudflare\\.com", confidence=0.7),
            ]
        )
    ]
    
    analyzer = AssetsAnalyzer(rules)
    detections = await analyzer.analyze(sample_context)
    
    assert len(detections) == 2
    names = {d.name for d in detections}
    assert "jsDelivr" in names
    assert "cdnjs" in names


@pytest.mark.asyncio
async def test_assets_analyzer_image_cdn(sample_context):
    rules = [
        Technology(
            name="Cloudinary",
            category="Image CDN",
            evidence_rules=[
                EvidenceRule(type="image_src_pattern", pattern="res\\.cloudinary\\.com", confidence=0.9),
            ]
        ),
        Technology(
            name="Cloudflare Images",
            category="Image CDN",
            evidence_rules=[
                EvidenceRule(type="image_src_pattern", pattern="imagedelivery\\.net", confidence=0.8),
            ]
        )
    ]
    
    analyzer = AssetsAnalyzer(rules)
    detections = await analyzer.analyze(sample_context)
    
    assert len(detections) == 2
    names = {d.name for d in detections}
    assert "Cloudinary" in names
    assert "Cloudflare Images" in names


@pytest.mark.asyncio
async def test_assets_analyzer_video_service(sample_context):
    rules = [
        Technology(
            name="YouTube",
            category="Video Service",
            evidence_rules=[
                EvidenceRule(type="html_pattern", pattern="youtube\\.com/embed", confidence=0.9),
            ]
        )
    ]
    
    analyzer = AssetsAnalyzer(rules)
    detections = await analyzer.analyze(sample_context)
    
    assert len(detections) == 1
    assert detections[0].name == "YouTube"
    assert detections[0].confidence == 0.9


@pytest.mark.asyncio
async def test_assets_analyzer_icons(sample_context):
    rules = [
        Technology(
            name="Material Icons",
            category="Icon Library",
            evidence_rules=[
                EvidenceRule(type="html_pattern", pattern='class=".*material-icons.*"', confidence=0.8),
            ]
        )
    ]
    
    analyzer = AssetsAnalyzer(rules)
    detections = await analyzer.analyze(sample_context)
    
    assert len(detections) == 1
    assert detections[0].name == "Material Icons"


@pytest.mark.asyncio
async def test_assets_analyzer_hosting(sample_context):
    rules = [
        Technology(
            name="Netlify",
            category="Hosting",
            evidence_rules=[
                EvidenceRule(type="header", name="Server", pattern="Netlify", confidence=0.9),
                EvidenceRule(type="header", name="X-NF-Request-ID", pattern=".", confidence=0.9),
            ]
        )
    ]
    
    analyzer = AssetsAnalyzer(rules)
    detections = await analyzer.analyze(sample_context)
    
    assert len(detections) == 2
    assert all(d.name == "Netlify" for d in detections)


@pytest.mark.asyncio
async def test_assets_analyzer_no_matches():
    """Test when no assets match"""
    context = ScanContext(
        url="https://example.com",
        headers={},
        html="<html><body>Simple page</body></html>",
        cookies={},
        scripts=[],
        stylesheets=[],
        js_globals=set(),
        tls=None,
        dns_records={}
    )
    
    rules = [
        Technology(
            name="Google Fonts",
            category="Font Service",
            evidence_rules=[
                EvidenceRule(type="css_link", pattern="fonts\\.googleapis\\.com", confidence=0.8),
            ]
        )
    ]
    
    analyzer = AssetsAnalyzer(rules)
    detections = await analyzer.analyze(context)
    
    assert len(detections) == 0
