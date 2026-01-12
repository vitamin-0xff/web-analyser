# Web Sites Analyser

A comprehensive web technology fingerprinting and detection engine that identifies CMS platforms, frameworks, libraries, CDNs, and infrastructure through HTTP headers, HTML content, JavaScript, DNS records, and more.

## Features

- **Multi-source Detection**: Analyzes HTTP headers, HTML, JavaScript, CSS, DNS, TLS, cookies, service metadata, inline scripts, forms, favicon hashes, SRI hashes, comments, and asset URLs
- **Modular Architecture**: 19 pluggable analyzers for different detection methods
- **Extensive Coverage**: 150+ technologies detected across web servers, frameworks, CMSs, CDNs, analytics, payments, hosting platforms
- **Confidence Aggregation**: Combines multiple evidence sources and caps confidence at 1.0
- **Async/Concurrent**: Non-blocking HTTP, DNS, and TLS operations
- **Rule-driven**: YAML-based detection rules for easy extension (10 rule files)
- **CLI & JSON Output**: Simple command-line interface with structured JSON output

## Installation

### Requirements
- Python 3.13+
- `uv` (or pip/venv)

### Setup

```bash
# Clone or navigate to the project
cd web-sites-analyser

# Install dependencies
uv sync

# Or with pip
pip install -r requirements.txt
```

## Usage

### Command Line

```bash
# Basic scan
uv run python3 main.py https://example.com

# With confidence threshold
uv run python3 main.py https://example.com --confidence-threshold 0.5

# Output (JSON)
[
  {
    "name": "Technology Name",
    "category": "Framework",
    "confidence": 0.8,
    "version": null,
    "evidence": {
      "type": "header",
      "name": "Server",
      "value": "nginx",
      "pattern": "nginx"
    }
  },
  ...
]
```

### Programmatic API

```python
import asyncio
from core.engine import Engine

async def main():
    engine = Engine()
    context = await engine.scan_url("https://example.com")
    detections = await engine.analyze_context(context)
    
    for detection in detections:
        print(f"{detection.name}: {detection.confidence}")

asyncio.run(main())
```

## Architecture

### Core Components

- **Engine** (`core/engine.py`): Orchestrates scanning and analysis. Fetches data, extracts features, and aggregates detections.
- **ScanContext** (`core/context.py`): Immutable data class holding all extracted information (headers, HTML, cookies, DNS records, etc.).
- **Analyzers** (`analyzers/`): Specialized modules analyzing specific data types and returning detections.
- **Rules** (`rules/`): YAML-based detection rules loaded into `Technology` and `EvidenceRule` objects.
- **Fetch Layer** (`fetch/`): Concurrent HTTP, DNS, and TLS information retrieval.

### Data Flow

```
URL
  ↓
scan_url() ──→ fetch HTTP, DNS, TLS ──→ parse HTML, extract JS/CSS/etc
  ↓
ScanContext (immutable)
  ↓
analyze_context() ──→ [HeadersAnalyzer, HtmlAnalyzer, JsAnalyzer, ...]
  ↓
List[Detection] ──→ _aggregate_detections() ──→ confidence summation
  ↓
Final detections (capped at 1.0 confidence)
```

## Analyzers

### Standard (6)
- **HeadersAnalyzer**: Detects via HTTP headers (Server, X-Powered-By, etc.)
- **HtmlAnalyzer**: Pattern matching in HTML content and comments
- **MetaTagsAnalyzer**: CMS signatures via `<meta>` tags (generator, author)
- **JsAnalyzer**: Script URLs and global variable detection
- **CssAnalyzer**: CSS framework detection via stylesheet URLs and class patterns
- **HTTPDetailsAnalyzer**: HTTP version, Server-Timing header analysis

### Extended (7)
- **NetworkAnalyzer**: DNS records (MX, TXT, NS), hosting providers, email security (SPF, DMARC)
- **TLSClientAnalyzer**: Certificate details, authorities, and TLS configuration
- **CookiesAnalyzer**: Technology signatures via cookie names/patterns
- **RobotsSitemapAnalyzer**: CMS fingerprinting from `/robots.txt` and `/sitemap.xml`
- **EndpointsAnalyzer**: GraphQL, OpenAPI, and API endpoint detection
- **StructuredDataAnalyzer**: Schema.org JSON-LD and microdata parsing
- **PWAAnalyzer**: Progressive Web App manifest and service worker detection

### Phase 1 Passive (5)
- **ScriptContentAnalyzer**: Inline JavaScript variable and function detection (window.wp, Shopify.theme, etc.)
- **FaviconAnalyzer**: CMS detection via favicon hash fingerprinting (MD5 hashes of favicon.ico)
- **FormsAnalyzer**: Framework detection through form patterns and hidden fields (_csrf, authenticity_token)
- **SRIAnalyzer**: Library detection via Subresource Integrity hash matching (Bootstrap, jQuery, etc.)
- **CommentsAnalyzer**: HTML/JS/CSS comment analysis for version strings and developer notes

### Assets (1)
- **AssetsAnalyzer**: Font detection (Google Fonts, Font Awesome), icon libraries, image CDNs (Cloudinary, Imgix), video services (YouTube, Vimeo), JS CDNs, and hosting platform fingerprints

## Detection Rules

Rules are defined in YAML files under `rules/`:

- **backend.yaml** (33 technologies): Web servers (Nginx, Apache, IIS), frameworks (Django, Rails, Laravel, Flask, FastAPI, Spring Boot), infrastructure (Cloudflare, HAProxy, Traefik)
- **frontend.yaml** (35 technologies): CMS (WordPress, Drupal, Joomla, Ghost), frameworks (React, Vue, Angular), static site generators (Gatsby, Hugo, Next.js, Astro), e-commerce (Magento, WooCommerce, Shopify)
- **javascript.yaml**: JavaScript libraries (jQuery, D3, Three.js), payment SDKs (Stripe, PayPal), auth providers (Auth0, Okta), analytics (GTM, Google Analytics, Segment, Mixpanel)
- **css.yaml** (27 frameworks): CSS frameworks (Bootstrap, Tailwind, Bulma, Foundation, Materialize, UIKit, Pure.css), icon libraries (Font Awesome, Bootstrap Icons)
- **cookies.yaml** (29 platforms): Session/auth cookies (WordPress, Django, Laravel, Drupal, Joomla), analytics (_ga, _gid), marketing (HubSpot, Marketo, Intercom)
- **network.yaml**: CDNs (Cloudflare, Akamai, Fastly), certificate authorities, email security (DMARC, DKIM), hosting providers
- **favicon.yaml** (5 CMS): WordPress, Joomla, Drupal, phpMyAdmin via favicon MD5 hashes
- **forms.yaml** (10 frameworks): Form signatures for Django, Rails, Laravel, Symfony, ASP.NET, Spring
- **sri.yaml** (10 libraries): SRI hash detection for Bootstrap, jQuery, Vue.js, React, Font Awesome
- **assets.yaml** (30+ rules): Font providers, icon libraries, image CDNs, video platforms, JS CDNs, hosting fingerprints

### Evidence Types

| Type | Example |
|------|---------|
| `header` | Server, X-Powered-By |
| `html_pattern` | DOCTYPE, HTML comments |
| `meta_tag` | generator, description |
| `js_url` | /jquery.min.js, /bootstrap.js |
| `js_global` | window.jQuery, Vue |
| `css_url` | /bootstrap.min.css, /tailwind.css |
| `css_class` | .container, .btn-primary |
| `cookie_name` | wordpress_logged_in, PHPSESSID |
| `cookie_domain` | .example.com |
| `dns_txt` | v=spf1, v=DMARC1 |
| `dns_mx` | mail.example.com |
| `dns_ns` | ns1.cloudflare.com |
| `tls_issuer` | Let's Encrypt, DigiCert |
| `tls_subject` | CN=example.com |
| `http_version` | HTTP/2, HTTP/3 |
| `server_timing_entry` | cdn-cache-hit |
| `script_src_pattern` | ga.js, analytics.js |
| `favicon_hash` | MD5 hash of favicon.ico |
| `form_action_pattern` | /wp-admin/post.php |
| `hidden_field_name` | _csrf, authenticity_token |
| `sri_hash` | sha384-ABC123... |
| `script_content_pattern` | window.wp, Shopify.theme |
| `inline_js_variable` | wp.config, Drupal.settings |
| `font_src_pattern` | fonts.googleapis.com |
| `image_src_pattern` | res.cloudinary.com |
| `video_embed_pattern` | youtube.com/embed |

## Confidence Model

Detections from multiple analyzers for the same technology are aggregated:

$$C_{total} = \min(1.0, \sum_i w_i)$$

Where $w_i$ is the confidence of each evidence source. This allows weak signals (e.g., a common class name) to combine with stronger ones.

## Testing

```bash
# Run all tests
uv run pytest -q

# Run specific test file
uv run pytest tests/test_engine.py -v

# Run with coverage
uv run pytest --cov=core --cov=analyzers tests/
```

### Test Files
- `tests/test_engine.py`: Rule filtering and detection aggregation
- `tests/test_new_analyzers.py`: Meta tags, structured data, PWA, robots/sitemap, storage analyzers

## Development

### Adding a New Analyzer

1. Create `analyzers/my_analyzer.py`:
```python
from typing import List
from core.context import ScanContext
from models.detection import Detection, Evidence
from models.technology import Technology

class MyAnalyzer:
    def __init__(self, rules: List[Technology]):
        self.rules = rules

    async def analyze(self, context: ScanContext) -> List[Detection]:
        detections: List[Detection] = []
        for tech in self.rules:
            for rule in tech.evidence_rules:
                if rule.type == "my_evidence_type":
                    # Detection logic
                    pass
        return detections
```

2. Register in `core/engine.py`:
```python
from analyzers.my_analyzer import MyAnalyzer

class Engine:
    def __init__(self):
        # ...
        self.my_analyzer = MyAnalyzer(
            _filter_technologies_by_rule_types(self.rules, {"my_evidence_type"})
        )
```

3. Call in `analyze_context()`:
```python
async def analyze_context(self, context: ScanContext) -> List[Detection]:
    # ...
    detections.extend(await self.my_analyzer.analyze(context))
    # ...
```

4. Add rules to corresponding YAML file

### Adding New Rules

1. Edit `rules/backend.yaml`, `rules/frontend.yaml`, etc.
2. Add a new technology entry:
```yaml
- name: My Technology
  category: Framework
  evidence:
    - type: header
      name: "X-My-Header"
      pattern: "mytech"
      confidence: 0.8
    - type: js_global
      pattern: "MyTech"
      confidence: 0.9
```

3. Test with CLI or unit tests

## Project Structure

```
web-sites-analyser/
├── analyzers/              # Detection modules
│   ├── headers.py
│   ├── html.py
│   ├── js.py
│   ├── cookies.py
│   ├── css.py
│   ├── network.py
│   ├── meta_tags.py
│   ├── structured_data.py
│   ├── pwa.py
│   ├── robots_sitemap.py
│   ├── http_details.py
│   ├── endpoints.py
│   ├── script_content.py   # Phase 1 passive
│   ├── favicon.py          # Phase 1 passive
│   ├── forms.py            # Phase 1 passive
│   ├── sri.py              # Phase 1 passive
│   ├── comments.py         # Phase 1 passive
│   └── assets.py           # Assets analyzer
├── core/
│   ├── context.py          # ScanContext data class
│   ├── engine.py           # Main orchestration
│   └── pipeline.py         # Analyzer pipeline (future)
├── fetch/
│   ├── http_client.py      # HTTP fetching
│   ├── dns_client.py       # DNS resolution
│   └── tls_client.py       # TLS certificate info
├── models/
│   ├── detection.py        # Detection data class
│   └── technology.py       # Technology and EvidenceRule
├── rules/
│   ├── backend.yaml        # Server/framework rules (33 technologies)
│   ├── frontend.yaml       # CMS/HTML rules (35 technologies)
│   ├── javascript.yaml     # JS library/SDK rules
│   ├── css.yaml            # CSS framework rules (27 frameworks)
│   ├── cookies.yaml        # Cookie detection rules (29 platforms)
│   ├── network.yaml        # DNS/TLS rules
│   ├── favicon.yaml        # Favicon hash rules (5 CMS)
│   ├── forms.yaml          # Form signature rules (10 frameworks)
│   ├── sri.yaml            # SRI hash rules (10 libraries)
│   ├── assets.yaml         # Asset detection rules (30+ rules)
│   └── rules_loader.py     # YAML loading
├── tests/
│   ├── conftest.py         # Pytest configuration
│   ├── test_engine.py      # Engine tests
│   ├── test_new_analyzers.py # New analyzer tests
│   ├── test_passive_analyzers.py # Phase 1 analyzer tests
│   └── test_assets_analyzer.py   # Assets analyzer tests
├── main.py                 # CLI entry point
├── pyproject.toml          # Project metadata & dependencies
└── README.md               # This file
```

## Branches

- `main` / `master`: Stable release
- `fix/analyzer-aggregation-and-cli`: Core engine fixes + CLI implementation
- `feat/extend-analyzer-rules`: Extended rule sets across all analyzers
- `feat/new-analyzers-meta-pwa-structured`: 7 new analyzers + extended JS/Network rules
- `feat/passive-analyzers-phase1`: Phase 1 passive analyzers implementation

## Examples

### Detect WordPress
```bash
$ uv run python3 main.py https://myblog.example.com --confidence-threshold 0.6
[
  {"name": "WordPress", "category": "CMS", "confidence": 0.9, ...},
  {"name": "Nginx", "category": "Web Server", "confidence": 0.8, ...},
  {"name": "Google Analytics", "category": "Analytics", "confidence": 0.8, ...}
]
```

### Detect React + TypeScript + Stripe
```bash
$ uv run python3 main.py https://myapp.example.com
[
  {"name": "React", "category": "Frontend Framework", "confidence": 1.0, ...},
  {"name": "Stripe.js", "category": "Payments", "confidence": 0.9, ...},
  {"name": "Cloudflare", "category": "CDN", "confidence": 0.9, ...}
]
```

## Performance Notes

- Fetches are concurrent (HTTP, DNS, TLS in parallel)
- Rule filtering per analyzer reduces redundant work
- Confidence aggregation is O(n) where n = total detections
- Average scan time: 2–5 seconds depending on site responsiveness

## Future Enhancements

- [ ] Phase 2: Active detection analyzers (GraphQL introspection, API probing, error message analysis)
- [ ] Phase 3: Advanced analyzers (WebAssembly, Web Components, WebSockets, service workers)
- [ ] Rule schema validation
- [ ] Output formatters (CSV, table, HTML)
- [ ] Caching for repeated scans
- [ ] CI/CD pipeline (GitHub Actions)
- [ ] Web UI dashboard
- [ ] Rate limiting & polite crawling
- [ ] Proxy support
- [ ] Historical tracking and change detection

## Contributing

1. Create a feature branch: `git checkout -b feat/my-feature`
2. Add tests for new functionality
3. Ensure all tests pass: `uv run pytest -q`
4. Commit and push: `git commit -m "feat: description" && git push`
5. Open a pull request

## License
Apache 2.0

## Authors

- **essid** - Main author and maintainer

## Acknowledgments

- Based on modular architecture principles from Wappalyzer and similar fingerprinting tools
- Detection patterns inspired by real-world web technology stacks
