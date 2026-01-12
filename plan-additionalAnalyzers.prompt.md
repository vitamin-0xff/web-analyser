# Additional Analyzers for Web-Sites-Analyser

## Overview
Proposed analyzers to extend detection capabilities across different web technologies and infrastructure patterns.

## Analyzer Candidates

### 1. Meta Tags Analyzer
**Purpose**: Detect CMS, frameworks, and tools via `<meta>` tags.

**Evidence Types**:
- `meta_name`: Match by `<meta name="..." content="...">` 
- `meta_property`: Match by `<meta property="..." content="...">` (Open Graph, JSON-LD)

**Implementation**:
- Leverage existing HTML context from [analyzers/html.py](analyzers/html.py)
- Parse all `<meta>` tags and create rules for known CMS/framework signatures
- No new fetch required

**Example Rules**:
```yaml
- name: Drupal
  category: CMS
  evidence:
    - type: meta_name
      name: "generator"
      pattern: "drupal"
      confidence: 0.8

- name: Open Graph
  category: SEO
  evidence:
    - type: meta_property
      name: "og:type"
      pattern: ".*"  # Any og: tag indicates social optimization
      confidence: 0.3
```

---

### 2. PWA / Manifest Analyzer
**Purpose**: Identify Progressive Web Applications and manifest configurations.

**Evidence Types**:
- `pwa_manifest`: Detect `rel="manifest"` link
- `service_worker`: Detect `navigator.serviceWorker` registrations

**Implementation**:
- Extend [core/context.py](core/context.py) with `manifest_url`, `service_worker_url` fields
- Parse `<link rel="manifest">` from HTML in [core/engine.py](core/engine.py)
- Scan inline scripts for `/sw.js`, `serviceWorker.register()` patterns
- Optional: fetch and parse `manifest.json` for app name, icons, categories

**Example Rules**:
```yaml
- name: PWA Present
  category: Architecture
  evidence:
    - type: pwa_manifest
      pattern: ".*"
      confidence: 0.6

- name: Service Worker
  category: Architecture
  evidence:
    - type: service_worker
      pattern: "serviceWorker"
      confidence: 0.7
```

---

### 3. Structured Data Analyzer
**Purpose**: Extract and parse JSON-LD, microdata, and RDFa for schema.org types and platforms.

**Evidence Types**:
- `json_ld_pattern`: Match schema.org `@type` values
- `microdata_pattern`: Match `itemtype` attributes

**Implementation**:
- Extend [analyzers/html.py](analyzers/html.py) to collect all `<script type="application/ld+json">` blocks
- Extract `@type` and `@context` fields
- Create rules for common types: `Product`, `Organization`, `NewsArticle`, `Event`
- Detect ecommerce platforms via structured data (e.g., `@type: Product` with schema.org pricing)

**Example Rules**:
```yaml
- name: Ecommerce Product Schema
  category: Ecommerce
  evidence:
    - type: json_ld_pattern
      pattern: '"@type"\s*:\s*"Product"'
      confidence: 0.5

- name: Organization Schema
  category: SEO
  evidence:
    - type: json_ld_pattern
      pattern: '"@type"\s*:\s*"Organization"'
      confidence: 0.3
```

---

### 4. Robots / Sitemap Analyzer
**Purpose**: Detect site structure, crawl directives, and SEO practices.

**Evidence Types**:
- `robots_txt`: Pattern matches in `/robots.txt` content
- `sitemap_pattern`: Presence of `/sitemap.xml` or `<link rel="sitemap">`

**Implementation**:
- Add lightweight fetch tasks to [core/engine.py](core/engine.py) for `/robots.txt` and `/sitemap.xml`
- Extend [core/context.py](core/context.py) with `robots_txt`, `sitemaps` fields
- Create rules for CMS signatures in Disallow paths (e.g., `/wp-admin/`, `/sites/default/`)
- Detect SEO frameworks and tools from sitemap sources

**Example Rules**:
```yaml
- name: WordPress (robots.txt)
  category: CMS
  evidence:
    - type: robots_txt
      pattern: '/wp-admin/|/wp-includes/'
      confidence: 0.8

- name: Drupal (robots.txt)
  category: CMS
  evidence:
    - type: robots_txt
      pattern: '/sites/default/files/'
      confidence: 0.7

- name: Sitemap Present
  category: SEO
  evidence:
    - type: sitemap_pattern
      pattern: 'sitemap'
      confidence: 0.4
```

---

### 5. Framework Paths Analyzer
**Purpose**: Infer CMS/frameworks from directory and file paths in links.

**Evidence Types**:
- `html_pattern`: Match file/path patterns in links, scripts, images

**Implementation**:
- Use existing HTML context; scan all `href`, `src` attributes
- Create patterns for known framework directories
- Low confidence due to false positives, but useful when combined with other signals

**Example Rules**:
```yaml
- name: WordPress (path markers)
  category: CMS
  evidence:
    - type: html_pattern
      pattern: '(wp-content|wp-includes|wp-json)'
      confidence: 0.5

- name: Drupal (path markers)
  category: CMS
  evidence:
    - type: html_pattern
      pattern: 'sites/default/files|modules/|sites/all/'
      confidence: 0.4
```

---

### 6. Service Endpoints Analyzer
**Purpose**: Detect API endpoints and architectural patterns.

**Evidence Types**:
- `graphql_endpoint`: Presence of `/graphql` endpoint
- `openapi_url`: Reference to OpenAPI/Swagger spec
- `api_pattern`: Path patterns like `/api/v1/`, `/rest/`

**Implementation**:
- Scan links and script data in HTML for endpoint references
- Search for OpenAPI/Swagger JSON in `<link>`, comments, or known paths
- Can optionally probe endpoints (low priority; may trigger WAF)

**Example Rules**:
```yaml
- name: GraphQL Endpoint
  category: API
  evidence:
    - type: html_pattern
      pattern: '/graphql'
      confidence: 0.7

- name: OpenAPI Available
  category: API
  evidence:
    - type: html_pattern
      pattern: '/swagger|/openapi\.json|/api-docs'
      confidence: 0.6
```

---

### 7. WebAssembly Analyzer
**Purpose**: Detect WebAssembly modules and runtime usage.

**Evidence Types**:
- `wasm_src`: URL patterns for `.wasm` files
- `js_global`: WebAssembly API usage (`WebAssembly`, `wasmBinary`)

**Implementation**:
- Extend [core/engine.py](core/engine.py) to capture `.wasm` file references
- Add field `wasm_modules: List[str]` to [core/context.py](core/context.py)
- Search inline scripts for `WebAssembly.instantiate()`, `wasmBinary` patterns

**Example Rules**:
```yaml
- name: WebAssembly Usage
  category: Architecture
  evidence:
    - type: wasm_src
      pattern: '\.wasm'
      confidence: 0.7
    - type: js_global
      pattern: 'WebAssembly|wasmBinary'
      confidence: 0.8
```

---

### 8. Asset Signatures Analyzer
**Purpose**: Identify frameworks and libraries via CDN asset URLs and font/icon patterns.

**Evidence Types**:
- `css_link`: CSS/font/icon library URLs
- `image_src_pattern`: Image paths and CDN patterns
- `font_src_pattern`: Font family URLs and @font-face declarations

**Implementation**:
- Extend [analyzers/css.py](analyzers/css.py) to detect `@import`, `@font-face`
- Scan `<link rel="stylesheet">` and `<script>` for inline font declarations
- Create rules for Material Icons, Font Awesome variants, Google Fonts

**Example Rules**:
```yaml
- name: Google Fonts
  category: Assets
  evidence:
    - type: css_link
      pattern: 'fonts\.googleapis\.com'
      confidence: 0.6

- name: Material Icons
  category: Icon Library
  evidence:
    - type: css_link
      pattern: 'material-icons|google-icons'
      confidence: 0.8
```

---

### 9. HTTP Details Analyzer
**Purpose**: Infer technologies from HTTP response metadata.

**Evidence Types**:
- `status_code`: Presence of custom status codes or ranges
- `server_timing`: Parse `Server-Timing` header for framework hints
- `http_version`: Detect HTTP/2, HTTP/3, QUIC support

**Implementation**:
- Extend [core/context.py](core/context.py) with `status_code`, `server_timing`, `http_version` fields
- Populate from [fetch/http_client.py](fetch/http_client.py) response metadata
- Create rules for framework/server signatures in custom headers

**Example Rules**:
```yaml
- name: HTTP/2 Support
  category: Infrastructure
  evidence:
    - type: http_version
      pattern: 'h2'
      confidence: 0.4

- name: Server-Timing Present
  category: Performance
  evidence:
    - type: server_timing
      pattern: '.*'
      confidence: 0.3
```

---

### 10. Storage Keys Analyzer
**Purpose**: Detect products and frameworks via localStorage/sessionStorage key patterns.

**Evidence Types**:
- `js_storage_key`: Patterns of `localStorage.getItem()` calls or key names

**Implementation**:
- Scan inline `<script>` content and extracted JS globals for storage access patterns
- Extend [analyzers/js.py](analyzers/js.py) to parse storage key references
- Look for patterns like `localStorage.setItem('auth0', ...)`, `sessionStorage.getItem('react')`

**Example Rules**:
```yaml
- name: Auth0 (localStorage)
  category: Identity
  evidence:
    - type: js_storage_key
      pattern: 'auth0|Auth0'
      confidence: 0.8

- name: Redux Store
  category: State Management
  evidence:
    - type: js_storage_key
      pattern: 'redux|__REDUX'
      confidence: 0.7
```

---

### 11. Payment / Identity SDKs Analyzer
**Purpose**: Extend JavaScript SDK detection beyond Stripe.

**Evidence Types**:
- `script_src`: PayPal, Square, Braintree, Adyen, Razorpay, etc.
- `js_global`: SDK global namespaces

**Implementation**:
- Extend [rules/javascript.yaml](rules/javascript.yaml) with payment and auth providers
- Add script CDN patterns and corresponding global variables

**Example Rules**:
```yaml
- name: PayPal Checkout
  category: Payments
  evidence:
    - type: script_src
      pattern: 'js\.paypal\.com'
      confidence: 0.9
    - type: js_global
      pattern: 'paypal'
      confidence: 0.9

- name: Auth0 SDK
  category: Identity
  evidence:
    - type: script_src
      pattern: 'cdn\.auth0\.com'
      confidence: 0.9
    - type: js_global
      pattern: 'auth0'
      confidence: 0.8
```

---

### 12. Analytics / Tag Manager Extensions
**Purpose**: Extend existing analytics rules with Segment, Mixpanel, Hotjar, and others.

**Evidence Types**:
- `script_src`: Analytics SDKs
- `js_global`: Analytics namespaces

**Implementation**:
- Extend [rules/javascript.yaml](rules/javascript.yaml)
- Add rules for Segment, Mixpanel, Hotjar, Matomo, etc.

**Example Rules**:
```yaml
- name: Segment Analytics
  category: Analytics
  evidence:
    - type: script_src
      pattern: 'cdn\.segment\.com'
      confidence: 0.9
    - type: js_global
      pattern: 'analytics'
      confidence: 0.7

- name: Hotjar
  category: Analytics
  evidence:
    - type: script_src
      pattern: 'static\.hotjar\.com'
      confidence: 0.8
    - type: js_global
      pattern: 'hj'
      confidence: 0.7
```

---

### 13. Email / Auth DNS Analyzer
**Purpose**: Extend DNS rules for email infrastructure and authentication.

**Evidence Types**:
- `dns_record` (TXT): DMARC, DKIM, DANE

**Implementation**:
- Extend [rules/network.yaml](rules/network.yaml)
- Add patterns for `v=DMARC1`, `v=DKIM1`, `TLSRPT`, `MTA-STS`

**Example Rules**:
```yaml
- name: DMARC Policy
  category: Email
  evidence:
    - type: dns_record
      name: "TXT"
      pattern: 'v=DMARC1'
      confidence: 0.6

- name: DKIM Signing
  category: Email
  evidence:
    - type: dns_record
      name: "TXT"
      pattern: 'v=DKIM1|k=rsa'
      confidence: 0.6
```

---

## Implementation Code Skeletons

### 1. Meta Tags Analyzer (`analyzers/meta_tags.py`)
```python
from typing import List
import re
from core.context import ScanContext
from models.detection import Detection, Evidence
from models.technology import Technology

class MetaTagsAnalyzer:
    def __init__(self, rules: List[Technology]):
        self.rules = rules

    async def analyze(self, context: ScanContext) -> List[Detection]:
        detections: List[Detection] = []
        html = context.html
        
        for tech in self.rules:
            for rule in tech.evidence_rules:
                if rule.type == "meta_name":
                    # Match <meta name="..." content="...">
                    pattern = f'<meta\\s+name=["\']?{rule.name}["\']?\\s+content=["\']([^"\']+)["\']'
                    match = re.search(pattern, html, re.IGNORECASE)
                    if match and re.search(rule.pattern, match.group(1), re.IGNORECASE):
                        detections.append(
                            Detection(
                                name=tech.name,
                                category=tech.category,
                                confidence=rule.confidence,
                                evidence=Evidence(
                                    type="meta_name",
                                    name=rule.name,
                                    value=match.group(1),
                                    pattern=rule.pattern
                                ),
                                version=tech.version
                            )
                        )
                
                elif rule.type == "meta_property":
                    # Match <meta property="..." content="...">
                    pattern = f'<meta\\s+property=["\']?{rule.name}["\']?\\s+content=["\']([^"\']+)["\']'
                    match = re.search(pattern, html, re.IGNORECASE)
                    if match and re.search(rule.pattern, match.group(1), re.IGNORECASE):
                        detections.append(
                            Detection(
                                name=tech.name,
                                category=tech.category,
                                confidence=rule.confidence,
                                evidence=Evidence(
                                    type="meta_property",
                                    name=rule.name,
                                    value=match.group(1),
                                    pattern=rule.pattern
                                ),
                                version=tech.version
                            )
                        )
        
        return detections
```

---

### 2. Structured Data Analyzer (`analyzers/structured_data.py`)
```python
from typing import List
import re
import json
from core.context import ScanContext
from models.detection import Detection, Evidence
from models.technology import Technology

class StructuredDataAnalyzer:
    def __init__(self, rules: List[Technology]):
        self.rules = rules

    async def analyze(self, context: ScanContext) -> List[Detection]:
        detections: List[Detection] = []
        html = context.html
        
        # Extract all JSON-LD blocks
        json_ld_pattern = r'<script\s+type=["\']application/ld\+json["\']>(.+?)</script>'
        json_ld_blocks = re.findall(json_ld_pattern, html, re.IGNORECASE | re.DOTALL)
        
        json_ld_text = ' '.join(json_ld_blocks)
        
        for tech in self.rules:
            for rule in tech.evidence_rules:
                if rule.type == "json_ld_pattern":
                    if re.search(rule.pattern, json_ld_text, re.IGNORECASE):
                        detections.append(
                            Detection(
                                name=tech.name,
                                category=tech.category,
                                confidence=rule.confidence,
                                evidence=Evidence(
                                    type="json_ld_pattern",
                                    pattern=rule.pattern,
                                    value=json_ld_text[:200]  # First 200 chars
                                ),
                                version=tech.version
                            )
                        )
        
        return detections
```

---

### 3. PWA Manifest Analyzer (`analyzers/pwa.py`)
```python
from typing import List
import re
from core.context import ScanContext
from models.detection import Detection, Evidence
from models.technology import Technology

class PWAAnalyzer:
    def __init__(self, rules: List[Technology]):
        self.rules = rules

    async def analyze(self, context: ScanContext) -> List[Detection]:
        detections: List[Detection] = []
        
        # Check for manifest presence
        has_manifest = bool(context.manifest_url)
        
        # Check for service worker
        has_service_worker = bool(context.service_worker_url)
        
        # Check for manifest-related script patterns
        has_pwa_patterns = bool(
            re.search(r'navigator\.serviceWorker|\/sw\.js|serviceWorker\.register', context.html, re.IGNORECASE)
        )
        
        for tech in self.rules:
            for rule in tech.evidence_rules:
                if rule.type == "pwa_manifest" and (has_manifest or has_pwa_patterns):
                    detections.append(
                        Detection(
                            name=tech.name,
                            category=tech.category,
                            confidence=rule.confidence,
                            evidence=Evidence(
                                type="pwa_manifest",
                                value=context.manifest_url or "inferred"
                            ),
                            version=tech.version
                        )
                    )
                
                elif rule.type == "service_worker" and has_service_worker:
                    detections.append(
                        Detection(
                            name=tech.name,
                            category=tech.category,
                            confidence=rule.confidence,
                            evidence=Evidence(
                                type="service_worker",
                                value=context.service_worker_url or "inferred"
                            ),
                            version=tech.version
                        )
                    )
        
        return detections
```

---

### 4. Robots/Sitemap Analyzer (`analyzers/robots_sitemap.py`)
```python
from typing import List
import re
from core.context import ScanContext
from models.detection import Detection, Evidence
from models.technology import Technology

class RobotsSitemapAnalyzer:
    def __init__(self, rules: List[Technology]):
        self.rules = rules

    async def analyze(self, context: ScanContext) -> List[Detection]:
        detections: List[Detection] = []
        
        robots_txt = context.robots_txt or ""
        sitemaps = context.sitemaps or []
        
        for tech in self.rules:
            for rule in tech.evidence_rules:
                if rule.type == "robots_txt" and robots_txt:
                    if re.search(rule.pattern, robots_txt, re.IGNORECASE):
                        detections.append(
                            Detection(
                                name=tech.name,
                                category=tech.category,
                                confidence=rule.confidence,
                                evidence=Evidence(
                                    type="robots_txt",
                                    pattern=rule.pattern,
                                    value=robots_txt[:200]
                                ),
                                version=tech.version
                            )
                        )
                
                elif rule.type == "sitemap_pattern":
                    if sitemaps and re.search(rule.pattern, ' '.join(sitemaps), re.IGNORECASE):
                        detections.append(
                            Detection(
                                name=tech.name,
                                category=tech.category,
                                confidence=rule.confidence,
                                evidence=Evidence(
                                    type="sitemap_pattern",
                                    pattern=rule.pattern,
                                    value=sitemaps[0] if sitemaps else "inferred"
                                ),
                                version=tech.version
                            )
                        )
        
        return detections
```

---

### 5. HTTP Details Analyzer (`analyzers/http_details.py`)
```python
from typing import List
from core.context import ScanContext
from models.detection import Detection, Evidence
from models.technology import Technology

class HTTPDetailsAnalyzer:
    def __init__(self, rules: List[Technology]):
        self.rules = rules

    async def analyze(self, context: ScanContext) -> List[Detection]:
        detections: List[Detection] = []
        
        status_code = context.status_code or ""
        http_version = context.http_version or ""
        server_timing = context.server_timing or ""
        
        for tech in self.rules:
            for rule in tech.evidence_rules:
                if rule.type == "http_version":
                    if http_version and rule.pattern in http_version:
                        detections.append(
                            Detection(
                                name=tech.name,
                                category=tech.category,
                                confidence=rule.confidence,
                                evidence=Evidence(
                                    type="http_version",
                                    value=http_version
                                ),
                                version=tech.version
                            )
                        )
                
                elif rule.type == "server_timing":
                    if server_timing:
                        detections.append(
                            Detection(
                                name=tech.name,
                                category=tech.category,
                                confidence=rule.confidence,
                                evidence=Evidence(
                                    type="server_timing",
                                    value=server_timing[:100]
                                ),
                                version=tech.version
                            )
                        )
        
        return detections
```

---

### 6. Storage Keys Analyzer (`analyzers/storage.py`)
```python
from typing import List
import re
from core.context import ScanContext
from models.detection import Detection, Evidence
from models.technology import Technology

class StorageAnalyzer:
    def __init__(self, rules: List[Technology]):
        self.rules = rules

    async def analyze(self, context: ScanContext) -> List[Detection]:
        detections: List[Detection] = []
        
        # Extract localStorage/sessionStorage key patterns from HTML and JS
        storage_pattern = r'(?:localStorage|sessionStorage)\.(?:setItem|getItem)\(["\']([^"\']+)["\']'
        storage_keys = re.findall(storage_pattern, context.html, re.IGNORECASE)
        storage_text = ' '.join(storage_keys)
        
        for tech in self.rules:
            for rule in tech.evidence_rules:
                if rule.type == "js_storage_key":
                    if re.search(rule.pattern, storage_text, re.IGNORECASE):
                        detections.append(
                            Detection(
                                name=tech.name,
                                category=tech.category,
                                confidence=rule.confidence,
                                evidence=Evidence(
                                    type="js_storage_key",
                                    pattern=rule.pattern,
                                    value=', '.join(storage_keys[:5])  # First 5 keys
                                ),
                                version=tech.version
                            )
                        )
        
        return detections
```

---

### 7. Service Endpoints Analyzer (`analyzers/endpoints.py`)
```python
from typing import List
import re
from core.context import ScanContext
from models.detection import Detection, Evidence
from models.technology import Technology

class EndpointsAnalyzer:
    def __init__(self, rules: List[Technology]):
        self.rules = rules

    async def analyze(self, context: ScanContext) -> List[Detection]:
        detections: List[Detection] = []
        
        # Combine all URLs: scripts, stylesheets, and links in HTML
        all_urls = context.scripts + context.stylesheets
        html_links = re.findall(r'href=["\']([^"\']+)["\']', context.html)
        all_urls.extend(html_links)
        urls_text = ' '.join(all_urls)
        
        for tech in self.rules:
            for rule in tech.evidence_rules:
                if rule.type in ["graphql_endpoint", "openapi_url", "api_pattern"]:
                    if re.search(rule.pattern, urls_text, re.IGNORECASE):
                        detections.append(
                            Detection(
                                name=tech.name,
                                category=tech.category,
                                confidence=rule.confidence,
                                evidence=Evidence(
                                    type=rule.type,
                                    pattern=rule.pattern,
                                    value=urls_text[:150]
                                ),
                                version=tech.version
                            )
                        )
        
        return detections
```

---

## Implementation Priority

### Phase 1 (Quick Wins - ~2–3 hours)
1. **Meta Tags Analyzer**: Uses existing HTML, minimal new code
2. **Framework Paths Analyzer**: Pattern matching on existing links
3. **Extended Rules** (JavaScript, Network): Add Payment SDKs, Analytics, DNS patterns

### Phase 2 (Medium Effort - ~4–6 hours)
1. **PWA / Manifest Analyzer**: Extend context and engine
2. **Structured Data Analyzer**: Parse JSON-LD blocks
3. **HTTP Details Analyzer**: Enrich context from response metadata


### Core Context Extensions (`core/context.py`)
```python
from dataclasses import dataclass
from typing import Dict, List, Set, Optional, Any

TLSInfo = Dict[str, Any]

@dataclass(frozen=True)
class ScanContext:
    url: str
    headers: Dict[str, str]
    html: str
    cookies: Dict[str, str]
    scripts: List[str]
    stylesheets: List[str]
    js_globals: Set[str]
    tls: Optional[TLSInfo]
    dns_records: Dict[str, List[str]]
    
    # NEW: PWA & Manifest
    manifest_url: Optional[str] = None
    service_worker_url: Optional[str] = None
    
    # NEW: HTTP metadata
    status_code: Optional[int] = None
    http_version: Optional[str] = None
    server_timing: Optional[str] = None
    
    # NEW: Robots & Sitemap
    robots_txt: Optional[str] = None
    sitemaps: Optional[List[str]] = None
    
    # NEW: WebAssembly
    wasm_modules: Optional[List[str]] = None
```

---

### Engine Extensions (`core/engine.py`)
```python
# In Engine.scan_url(), add:

# Parse PWA manifest link
manifest_match = re.search(r'<link\s+rel=["\']manifest["\'][^>]*href=["\']([^"\']+)["\']', html_content)
manifest_url = urljoin(url, manifest_match.group(1)) if manifest_match else None

# Parse service worker registration
service_worker_match = re.search(r'navigator\.serviceWorker\.register\(["\']([^"\']+)["\']', html_content)
service_worker_url = urljoin(url, service_worker_match.group(1)) if service_worker_match else None

# Extract WASM modules
wasm_modules = [urljoin(url, src) for src in re.findall(r'["\']([^"\']*\.wasm)["\']', html_content)]

# Fetch robots.txt and sitemap.xml (async)
async def fetch_robots_txt(url: str):
    try:
        base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        resp = await fetch_url(f"{base_url}/robots.txt")
        return resp.text if resp.status_code == 200 else None
    except:
        return None

async def fetch_sitemaps(url: str, robots_txt: str):
    sitemaps = []
    if robots_txt:
        sitemap_urls = re.findall(r'Sitemap:\s*(.+)', robots_txt)
        sitemaps.extend(sitemap_urls)
    # Also check common locations
    for path in ['/sitemap.xml', '/sitemap_index.xml']:
        base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        try:
            resp = await fetch_url(f"{base_url}{path}")
            if resp.status_code == 200:
                sitemaps.append(f"{base_url}{path}")
        except:
            pass
    return sitemaps

# Add to scan_url:
robots_txt = await fetch_robots_txt(url)
sitemaps = await fetch_sitemaps(url, robots_txt or "")

# Enhance context with HTTP metadata
context = ScanContext(
    url=url,
    headers=headers,
    html=html_content,
    cookies=cookies,
    scripts=scripts,
    stylesheets=stylesheets,
    js_globals=js_globals,
    tls=tls_info,
    dns_records=dns_records,
    manifest_url=manifest_url,
    service_worker_url=service_worker_url,
    status_code=response.status_code,
    http_version=response.http_version,
    server_timing=response.headers.get('Server-Timing'),
    robots_txt=robots_txt,
    sitemaps=sitemaps,
    wasm_modules=wasm_modules
)
```

---

### Extended Rules: JavaScript/Payment SDKs (`rules/javascript.yaml`)
```yaml
# Payment Gateways
- name: PayPal Checkout
  category: Payments
  evidence:
    - type: script_src
      pattern: 'js\.paypal\.com'
      confidence: 0.9
    - type: js_global
      pattern: 'paypal|PAYPAL'
      confidence: 0.8

- name: Square
  category: Payments
  evidence:
    - type: script_src
      pattern: 'square\.github\.io|paysquare'
      confidence: 0.8
    - type: js_global
      pattern: 'SqPaymentForm'
      confidence: 0.9

- name: Braintree
  category: Payments
  evidence:
    - type: script_src
      pattern: 'braintree'
      confidence: 0.9
    - type: js_global
      pattern: 'braintree'
      confidence: 0.8

# Identity & Auth
- name: Auth0
  category: Identity
  evidence:
    - type: script_src
      pattern: 'cdn\.auth0\.com'
      confidence: 0.9
    - type: js_global
      pattern: 'Auth0|auth0'
      confidence: 0.8

- name: Okta
  category: Identity
  evidence:
    - type: script_src
      pattern: 'okta\.com|oktacdn'
      confidence: 0.9
    - type: js_global
      pattern: 'OktaAuth'
      confidence: 0.8

- name: Firebase Auth
  category: Identity
  evidence:
    - type: script_src
      pattern: 'firebase'
      confidence: 0.7
    - type: js_global
      pattern: 'firebase|FirebaseAuth'
      confidence: 0.8

# Analytics Extensions
- name: Segment
  category: Analytics
  evidence:
    - type: script_src
      pattern: 'cdn\.segment\.com|analytics\.js'
      confidence: 0.9
    - type: js_global
      pattern: 'analytics'
      confidence: 0.7

- name: Mixpanel
  category: Analytics
  evidence:
    - type: script_src
      pattern: 'mixpanel\.com'
      confidence: 0.9
    - type: js_global
      pattern: 'mixpanel'
      confidence: 0.8

- name: Hotjar
  category: Analytics
  evidence:
    - type: script_src
      pattern: 'static\.hotjar\.com'
      confidence: 0.8
    - type: js_global
      pattern: 'hj'
      confidence: 0.6

- name: Matomo
  category: Analytics
  evidence:
    - type: script_src
      pattern: 'matomo|piwik'
      confidence: 0.8
    - type: js_global
      pattern: '_paq'
      confidence: 0.8
```

---

### Extended Rules: Network/DNS (`rules/network.yaml`)
```yaml
# Email Security
- name: DMARC Policy
  category: Email Security
  evidence:
    - type: dns_record
      name: "TXT"
      pattern: 'v=DMARC1'
      confidence: 0.6

- name: DKIM Signing
  category: Email Security
  evidence:
    - type: dns_record
      name: "TXT"
      pattern: 'v=DKIM1'
      confidence: 0.6

- name: MTA-STS
  category: Email Security
  evidence:
    - type: dns_record
      name: "TXT"
      pattern: 'v=STSv1'
      confidence: 0.6

# Email Service Providers
- name: Mailgun
  category: Email
  evidence:
    - type: dns_record
      name: "CNAME"
      pattern: 'mailgun\.org'
      confidence: 0.8

- name: SendGrid
  category: Email
  evidence:
    - type: dns_record
      name: "CNAME"
      pattern: 'sendgrid'
      confidence: 0.8

- name: Mailchimp
  category: Email
  evidence:
    - type: dns_record
      name: "CNAME"
      pattern: 'mailchimp'
      confidence: 0.7
```

---

### Sample Tests (`tests/test_new_analyzers.py`)
```python
import asyncio
from core.context import ScanContext
from analyzers.meta_tags import MetaTagsAnalyzer
from analyzers.structured_data import StructuredDataAnalyzer
from analyzers.pwa import PWAAnalyzer
from models.technology import Technology, EvidenceRule

def test_meta_tags_analyzer():
    html = '''
    <meta name="generator" content="Drupal 9">
    <meta property="og:type" content="website">
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
    html = '''
    <script type="application/ld+json">
    {"@type": "Product", "@context": "https://schema.org"}
    </script>
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
```

---



### New Analyzers
- `analyzers/meta_tags.py`: Extract `<meta>` signatures
- `analyzers/pwa.py`: Detect PWA manifest and service workers
- `analyzers/structured_data.py`: Parse JSON-LD and schema.org types
- `analyzers/robots_sitemap.py`: Fetch and analyze `/robots.txt`, `/sitemap.xml`
- `analyzers/http_details.py`: Infer from HTTP response metadata
- `analyzers/storage.py`: Detect storage key patterns
- `analyzers/endpoints.py`: Identify API endpoints and OpenAPI

### Extended Core Files
- `core/context.py`: Add fields for `manifest_url`, `robots_txt`, `sitemaps`, `status_code`, `server_timing`, `http_version`, `wasm_modules`
- `core/engine.py`: Fetch `/robots.txt`, `/sitemap.xml`; extract PWA manifest, WASM, service worker refs
- `rules/javascript.yaml`: Add Payment SDKs, Auth providers, Analytics (Segment, Mixpanel, Hotjar)
- `rules/network.yaml`: Add Email security (DMARC, DKIM)

### Tests
- `tests/test_meta_tags.py`
- `tests/test_pwa.py`
- `tests/test_structured_data.py`
- etc.

---

## Notes

- **Incremental approach**: Start with Phase 1 to add value quickly without major refactors.
- **Backward compatibility**: New context fields should be optional (default to `None` or empty lists).
- **Rule extensibility**: All new analyzers follow the same pattern: filter rules, iterate rules, match patterns, yield detections.
- **Testing**: Unit tests per analyzer; sample YAMLs in `rules/` with 5–10 entries per category.
