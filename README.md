# Web Sites Analyser

A comprehensive web technology fingerprinting and detection engine that identifies CMS platforms, frameworks, libraries, CDNs, and infrastructure through HTTP headers, HTML content, JavaScript, DNS records, and more.

## Features

- **Multi-source Detection**: Analyzes HTTP headers, HTML, JavaScript, CSS, DNS, TLS, cookies, and service metadata
- **Modular Architecture**: Pluggable analyzers for different detection methods
- **Confidence Aggregation**: Combines multiple evidence sources and caps confidence at 1.0
- **Async/Concurrent**: Non-blocking HTTP, DNS, and TLS operations
- **Rule-driven**: YAML-based detection rules for easy extension
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
- **JsAnalyzer**: Script URLs and global variable detection
- **CookiesAnalyzer**: Technology signatures via cookie names/patterns
- **CssAnalyzer**: CSS framework detection via stylesheet URLs and class patterns
- **NetworkAnalyzer**: TLS issuer/subject and DNS record patterns

### Extended (7)
- **MetaTagsAnalyzer**: CMS signatures via `<meta>` tags
- **StructuredDataAnalyzer**: Schema.org JSON-LD and microdata parsing
- **PWAAnalyzer**: Progressive Web App manifest and service worker detection
- **RobotsSitemapAnalyzer**: CMS fingerprinting from `/robots.txt` and `/sitemap.xml`
- **HTTPDetailsAnalyzer**: HTTP version, Server-Timing header analysis
- **StorageAnalyzer**: localStorage/sessionStorage key patterns
- **EndpointsAnalyzer**: GraphQL, OpenAPI, and API endpoint detection

## Detection Rules

Rules are defined in YAML files under `rules/`:

- **backend.yaml**: Web servers (Nginx, Apache, IIS), frameworks (Django, Rails, ASP.NET)
- **frontend.yaml**: CMS (WordPress, Drupal, Jekyll), frameworks (React, Vue, Angular via HTML)
- **javascript.yaml**: JavaScript libraries and frameworks (jQuery, D3, Three.js, etc.), payment SDKs (Stripe, PayPal), auth providers (Auth0, Okta), analytics (GTM, Google Analytics, Segment, Mixpanel)
- **css.yaml**: CSS frameworks (Bootstrap, Tailwind, Bulma), icon libraries (Font Awesome)
- **cookies.yaml**: Session/auth cookies (WordPress, Django, Laravel), analytics (_ga, _gid)
- **network.yaml**: CDNs (Cloudflare, Akamai, Fastly), certificate authorities, email security (DMARC, DKIM)

### Evidence Types

| Type | Example |
|------|---------|
| `header` | Server, X-Powered-By |
| `cookie` | sessionid, PHPSESSID |
| `html_pattern` | `<div id="app">` (Vue.js) |
| `html_comment` | Jekyll comments |
| `script_src` | jQuery CDN URLs |
| `js_global` | window.React, window.jQuery |
| `css_link` | Bootstrap CDN |
| `meta_name` | generator meta tag |
| `meta_property` | Open Graph properties |
| `json_ld_pattern` | Schema.org @type patterns |
| `pwa_manifest` | Web App Manifest presence |
| `service_worker` | Service Worker registration |
| `robots_txt` | Path patterns in /robots.txt |
| `sitemap_pattern` | Sitemap.xml presence |
| `tls_issuer` | Certificate issuer organization |
| `dns_record` | A, CNAME, TXT, MX records |
| `http_version` | HTTP/2, HTTP/3 support |
| `server_timing` | Server-Timing header |
| `js_storage_key` | localStorage/sessionStorage keys |
| `graphql_endpoint` | /graphql URL presence |
| `openapi_url` | OpenAPI/Swagger references |

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
│   ├── storage.py
│   └── endpoints.py
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
│   ├── backend.yaml        # Server/framework rules
│   ├── frontend.yaml       # CMS/HTML rules
│   ├── javascript.yaml     # JS library/SDK rules
│   ├── css.yaml            # CSS framework rules
│   ├── cookies.yaml        # Cookie detection rules
│   ├── network.yaml        # DNS/TLS rules
│   └── rules_loader.py     # YAML loading
├── tests/
│   ├── conftest.py         # Pytest configuration
│   ├── test_engine.py      # Engine tests
│   └── test_new_analyzers.py # New analyzer tests
├── main.py                 # CLI entry point
├── pyproject.toml          # Project metadata & dependencies
└── README.md               # This file
```

## Branches

- `main` / `master`: Stable release
- `fix/analyzer-aggregation-and-cli`: Core engine fixes + CLI implementation
- `feat/extend-analyzer-rules`: Extended rule sets across all analyzers
- `feat/new-analyzers-meta-pwa-structured`: 7 new analyzers + extended JS/Network rules

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

- [ ] Rule schema validation
- [ ] Output formatters (CSV, table, HTML)
- [ ] Caching for repeated scans
- [ ] WebAssembly module detection (WIP)
- [ ] CI/CD pipeline (GitHub Actions)
- [ ] Web UI dashboard
- [ ] Rate limiting & polite crawling
- [ ] Proxy support

## Contributing

1. Create a feature branch: `git checkout -b feat/my-feature`
2. Add tests for new functionality
3. Ensure all tests pass: `uv run pytest -q`
4. Commit and push: `git commit -m "feat: description" && git push`
5. Open a pull request

## License

[Specify your license here, e.g., MIT, Apache 2.0]

## Authors

- **essid** - Main author and maintainer

## Acknowledgments

- Based on modular architecture principles from Wappalyzer and similar fingerprinting tools
- Detection patterns inspired by real-world web technology stacks
