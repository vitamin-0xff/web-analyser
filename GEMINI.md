## Gemini Project Guidelines: Website Technology Fingerprinting CLI

This document provides a summary of the project's goals, architecture, and conventions to guide development.

### 1. Core Objective

The primary goal is to build a passive technology-fingerprinting engine that analyzes websites to identify their underlying technologies. Given a URL, the tool inspects HTTP headers, HTML, JavaScript, CSS, DNS, TLS metadata, cookies, forms, inline scripts, favicon hashes, SRI hashes, comments, and asset URLs to produce a structured list of 150+ detected technologies with confidence scores.

### 2. Architecture

The project follows a modular architecture:

-   `main.py`: Command-line interface entry point
-   `core/`: Orchestration engine (`engine.py`), ScanContext (`context.py`), and pipeline
-   `fetch/`: Modules for fetching data (HTTP, DNS, TLS)
-   `analyzers/`: 19 components that analyze different data sources
    -   **Standard (6)**: Headers, HTML, Meta Tags, JavaScript, CSS, HTTP Details
    -   **Extended (7)**: Network, TLS Client, Cookies, Robots/Sitemap, Endpoints, Structured Data, PWA
    -   **Phase 1 Passive (5)**: Script Content, Favicon, Forms, SRI, Comments
    -   **Assets (1)**: Font/Icon/CDN/Hosting detection
-   `rules/`: 10 YAML files with detection rules (backend, frontend, javascript, css, cookies, network, favicon, forms, sri, assets)
-   `models/`: Data structures for detections (`detection.py`) and technologies (`technology.py`)
-   `tests/`: Comprehensive test suite (21 tests) with pytest + pytest-asyncio

### 3. Key Design Principles

-   **Single Responsibility:** Each analyzer has a single, well-defined purpose
-   **Loose Coupling:** Modules interact through a shared, immutable `ScanContext` object
-   **Open-Closed Principle:** New technologies added via YAML rules without code changes
-   **Deterministic Execution:** Same input produces same output
-   **Immutability**: ScanContext is frozen dataclass, read-only after creation
-   **Async-first**: All I/O operations use asyncio/httpx for concurrent execution
-   **Evidence-based**: Every detection includes provenance (type, value, pattern)

### 4. Detection Strategy

-   **Multi-layered Evidence:** Combines 27+ evidence types from HTTP, HTML, JavaScript, CSS, DNS, TLS, cookies, forms, assets, and passive signatures
-   **Hit Types:** header, html_pattern, meta_tag, js_url, js_global, css_url, css_class, cookie_name, cookie_domain, dns_txt, dns_mx, dns_ns, tls_issuer, tls_subject, http_version, server_timing_entry, script_src_pattern, favicon_hash, form_action_pattern, hidden_field_name, sri_hash, script_content_pattern, inline_js_variable, font_src_pattern, image_src_pattern, video_embed_pattern
-   **Confidence Scoring:** $$C_{total} = \min(1.0, \sum_i confidence_i)$$ - Multiple weak signals strengthen detection, capped at 1.0

### 5. `ScanContext`

A central, immutable `ScanContext` dataclass holds all the data fetched for a target URL:

```python
@dataclass(frozen=True)
class ScanContext:
    url: str
    status_code: int | None
    headers: dict[str, str]
    body: str
    html: BeautifulSoup | None
    scripts: list[str]              # <script src="...">
    stylesheets: list[str]          # <link rel="stylesheet" href="...">
    meta_tags: dict[str, str]
    cookies: dict[str, dict]
    dns_records: dict[str, list]    # A, MX, TXT, NS
    tls_info: dict | None
    json_ld: list[dict]
    pwa_manifest: dict | None
    robots_txt: str | None
    inline_scripts: list[str]       # <script>...</script> content
    forms: list[dict]               # Action, method, input fields
    comments: list[str]             # HTML/JS/CSS comments
    favicon_hash: str | None        # MD5 hash of favicon
    sri_hashes: list[dict]          # {algorithm, hash, url}
    asset_urls: dict[str, list]     # fonts, images, videos, icons
```

### 6. CLI Usage

```bash
# Basic scan
uv run python3 main.py https://example.com

# With confidence threshold
uv run python3 main.py https://example.com --confidence-threshold 0.5

# Output is JSON array of detections
```

Common flags include `--confidence-threshold` to filter results.

### 7. Recent Developments

-   **Phase 1 Passive Analyzers (5)**: Script Content, Favicon, Forms, SRI, Comments
-   **Expanded Rules**: 79 new technologies added (33 backend, 35 frontend, 27 css, 29 cookies)
-   **Assets Analyzer**: Detects fonts, icons, image CDNs, video platforms, JS CDNs, hosting
-   **Total Coverage**: 150+ technologies across 10 YAML rule files
-   **Test Suite**: 21 passing tests covering all analyzers

### 8. Version Control (Git)

-   All new features or bug fixes developed in separate branches
-   Branch naming: `feat/feature-name`, `fix/bug-name`
-   Recent branches: `feat/passive-analyzers-phase1` (merged)

### 9. Inspiration

The project is inspired by **Wappalyzer**. The goal is to act as a passive, modular, deterministic, and extensible fingerprinting engine with broader coverage and evidence transparency.
