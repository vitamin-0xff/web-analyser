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
