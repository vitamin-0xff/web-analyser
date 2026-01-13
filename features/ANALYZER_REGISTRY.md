# Dynamic Analyzer Registry

## Overview

The analyzer registry system enables dynamic discovery and selective execution of technology detection analyzers through a decorator-based pattern.

## Features

### 1. Decorator-Based Registration
All analyzers use `@AnalyzerRegistry.register()` decorator:

```python
from core.analyzer_registry import AnalyzerRegistry, filter_by_rule_types

@AnalyzerRegistry.register(
    "headers",
    lambda rules: filter_by_rule_types(rules, {"header"})
)
class HeadersAnalyzer:
    def __init__(self, rules: List[Technology]):
        self.rules = rules
    
    async def analyze(self, context: ScanContext) -> List[Detection]:
        # Detection logic
        pass
```

### 2. Dynamic Instantiation
Engine automatically discovers and instantiates all registered analyzers:

```python
engine = Engine()  # All analyzers enabled
engine = Engine(exclude_analyzers={'html', 'css'})  # Exclude specific analyzers
```

### 3. CLI Integration

**List available analyzers:**
```bash
uv run main.py --list-analyzers
```

**Exclude specific analyzers:**
```bash
uv run main.py https://example.com --exclude html comments css
```

**Scan with all analyzers (default):**
```bash
uv run main.py https://example.com
```

## Available Analyzers

- `headers` - HTTP headers analysis
- `html` - HTML pattern matching
- `js` - JavaScript library detection
- `cookies` - Cookie-based detection
- `network` - DNS/TLS analysis
- `css` - CSS framework detection
- `meta_tags` - Meta tag analysis
- `structured_data` - JSON-LD/Schema.org
- `pwa` - Progressive Web App detection
- `robots_sitemap` - robots.txt/sitemap analysis
- `http_details` - HTTP version/Server-Timing
- `storage` - LocalStorage/SessionStorage
- `endpoints` - API endpoint detection
- `script_content` - Inline script analysis
- `favicon` - Favicon hash matching
- `forms` - Form analysis
- `sri` - Subresource Integrity
- `comments` - HTML/CSS/JS comments
- `assets` - Asset fingerprinting

## Benefits

1. **No Manual Maintenance** - Adding a new analyzer only requires the decorator
2. **Type-Safe** - Analyzers must implement `analyze()` method
3. **Automatic Rule Filtering** - Rules filtered per analyzer automatically
4. **Easy Testing** - `AnalyzerRegistry.clear()` for test isolation
5. **Selective Execution** - Skip slow/unnecessary analyzers
6. **Backward Compatible** - All analyzers enabled by default

## Adding a New Analyzer

1. Create analyzer file in `analyzers/`
2. Add the decorator:
```python
@AnalyzerRegistry.register(
    "my_analyzer",
    lambda rules: filter_by_rule_types(rules, {"my_rule_type"})
)
class MyAnalyzer:
    def __init__(self, rules: List[Technology]):
        self.rules = rules
    
    async def analyze(self, context: ScanContext) -> List[Detection]:
        # Your logic here
        return detections
```
3. Import in `core/engine.py`:
```python
import analyzers.my_analyzer
```
4. Done! The analyzer is automatically registered and available

## Performance Tips

- Use `--exclude` to skip expensive analyzers (e.g., `html` for large pages)
- Check `--list-analyzers` to see all available options
- Each analyzer has a 10s timeout to prevent hangs

## Phase 2: Active Detection Analyzers

Phase 2 adds **active probing** analyzers that make HTTP requests to detect technologies. These are disabled by default to avoid impacting target systems.

### Active Analyzers (Opt-in)

#### GraphQL Introspection
Probes for GraphQL endpoints and introspects schemas to detect server implementations.

```bash
# Enable with --active flag
uv run main.py https://example.com --active
```

**Endpoints probed:**
- `/graphql`, `/api/graphql`, `/api/v1/graphql`
- `/query`, `/api/query`, `/gql`
- And 3 more common variants

**Detections:**
- Apollo GraphQL (0.9 confidence)
- Hasura (0.95 confidence)
- GraphQL Yoga
- AWS AppSync

#### API Probing
Discovers REST API endpoints and analyzes responses to detect frameworks.

**Endpoints probed:**
- `/api`, `/api/v1`, `/api/v2`, `/v1-3`
- `/swagger.json`, `/openapi.json`
- `/api/docs`, `/health`, `/status`, `/version`
- And more

**Detections:**
- FastAPI (0.9 confidence)
- Django REST Framework
- Express.js
- Flask
- Spring Boot
- ASP.NET Core
- Ruby on Rails
- Laravel

#### Error Message Analysis
Triggers errors to fingerprint technologies from error pages.

**Methods:**
- Requests non-existent paths (`/api/nonexistent`, `/nonexistent.php`)
- Analyzes error messages (500 status)
- Parses stack traces

**Detections:**
- Backend frameworks (Django, Flask, Rails)
- Database errors (PostgreSQL, MySQL, MongoDB)
- Web servers (Nginx, Apache, IIS)
- Cloud platforms (AWS Lambda, Google Cloud, Azure)

### Usage

**Default (Passive Only):**
```bash
uv run main.py https://example.com
# Only uses: headers, html, js, css, etc. (19 analyzers)
# No extra HTTP requests to target
```

**With Active Detection:**
```bash
uv run main.py https://example.com --active
# Includes: graphql, api_probe, error_probe (22 total analyzers)
# Makes ~10-15 additional HTTP requests
```

**Exclude Specific Active Analyzers:**
```bash
# Run active but skip error probing
uv run main.py https://example.com --active --exclude error_probe

# Run active but skip API and error probing
uv run main.py https://example.com --active --exclude api_probe error_probe
```

### Performance

- Passive scan: ~7 seconds (jQuery.com)
- Active scan: ~10 seconds (+3 second overhead for probing)
- Each active analyzer has 5 second timeout
- Limited to 10-15 HTTP requests per analyzer

### Safety & Ethical Usage

⚠️ **Active detection makes HTTP requests to the target system:**
- Always get permission before scanning
- Respects HTTP status codes (404, 401, etc.)
- Limits probes to common paths
- Reasonable timeouts prevent resource exhaustion
- Does not attempt exploitation, only detection

### Detection Quality

| Analyzer | Techniques | Confidence | False Positives |
|----------|-----------|-----------|-----------------|
| graphql | Introspection responses | 0.9-1.0 | Very low |
| api_probe | Response headers, JSON structure | 0.5-0.9 | Medium |
| error_probe | Error messages, stack traces | 0.8-0.9 | Low |

### Examples

**Detect GraphQL on example.com:**
```bash
uv run main.py https://example.com --active
# Output: "Apollo GraphQL" or "Hasura" if GraphQL detected
```

**Fingerprint backend stack:**
```bash
uv run main.py https://example.com --active --exclude graphql
# Uses API probing + error triggering
# Detects: Flask, PostgreSQL, Nginx, etc.
```

**Check what analyzers will run:**
```bash
uv run main.py --list-analyzers
# Lists all 22 analyzers (19 passive + 3 active)
```

