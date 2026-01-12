# Web Sites Analyser - Roadmap

## Completed ✅

- [x] Phase 1 Passive Analyzers (5 analyzers: script_content, favicon, forms, sri, comments)
- [x] Expanded Rule Coverage (79 new technologies across backend, frontend, css, cookies)
- [x] Assets Analyzer (30+ rules for fonts, icons, CDNs, hosting)
- [x] Documentation updates (README, GEMINI, GUIDELINES)

## High Priority

### 1. CI/CD Pipeline 🔄
**Status**: Not Started

Set up GitHub Actions for automated testing and quality checks:
- Run pytest on every push/PR
- Code coverage reporting (codecov.io)
- Linting (ruff/pylint)
- Type checking (mypy)
- Automated releases with tags

### 2. Performance Optimization ⚡
**Status**: Mostly Complete - Core improvements done, profiling/UI pending

Address slow scan issues and improve efficiency:
- Profile the engine to find remaining bottlenecks
- ✅ Add request timeouts (HTTP 10s, DNS 5s, TLS 5s)
- ✅ Implement caching for repeated scans (robots.txt 10min, favicon 1hr)
- Parallelize analyzer execution where possible
- Add progress indicators for long scans

**Implementation Tasks**:
- [x] Add timeout configurations to HTTP/DNS/TLS clients
- [x] Implement in-memory caching for static resources (core/cache.py)
- [ ] Profile slow scans to identify remaining bottlenecks
- [ ] Add progress indicators

### 3. Version Detection Enhancement 🔍
**Status**: In Progress

Many detections show `"version": null` - improve version extraction:
- Add version extraction patterns to existing rules
- Parse version from meta tags, JS comments, file paths
- Extract from library URLs (`jquery-3.6.0.min.js`)
- Version-specific patterns in HTML/JS

**Implementation Tasks**:
- [ ] Add version regex patterns to YAML rules
- [ ] Implement version extractor utility functions
- [ ] Update analyzers to extract versions from URLs
- [ ] Parse versions from meta tags (generator, application-version)
- [ ] Extract versions from JS comments and inline code
- [ ] Add version detection tests

### 4. Output Formatters 📊
**Status**: Not Started

Make results more user-friendly:
- Table format (tabulate/rich library)
- CSV export for spreadsheet analysis
- HTML report with charts
- Markdown summary format
- Filter by category/confidence

## Medium Priority

### 5. Phase 2: Active Detection 🎯
**Status**: Planned

Implement active analyzers (requires careful rate limiting):
- GraphQL introspection (schema queries)
- API endpoint probing (404 error pages revealing tech)
- Error message analysis (stack traces)
- Response time fingerprinting
- HTTP method enumeration

### 6. Configuration System ⚙️
**Status**: Not Started

Add user-configurable settings:
- `config.yaml` or `.env` file support
- Timeout values (HTTP, DNS, TLS)
- User-Agent customization
- Proxy configuration
- Enable/disable specific analyzers
- Custom rule directories

### 7. Batch Scanning 📝
**Status**: Not Started

Scan multiple URLs efficiently:
- Read URLs from file (`--urls-file urls.txt`)
- Parallel scanning with concurrency limit
- Progress bar for batch operations
- Aggregate statistics across scans
- Compare results between URLs

### 8. Error Handling & Resilience 🛡️
**Status**: Not Started

Make the engine more robust:
- Retry logic for failed requests
- Graceful degradation (continue on partial failures)
- Better error messages with suggestions
- Logging levels (debug, info, warning, error)
- Validation for invalid URLs

## Lower Priority

### 9. Web UI Dashboard 🌐
**Status**: Planned

Visual interface for results:
- FastAPI/Flask backend
- React/Vue frontend
- Real-time scan progress
- Historical scan storage (SQLite/PostgreSQL)
- Comparison views

### 10. Plugin System 🔌
**Status**: Planned

Allow external analyzers:
- Dynamic analyzer loading
- Plugin manifest format
- Community analyzer marketplace
- Custom rule loader hooks

### 11. API Mode 🚀
**Status**: Planned

Run as a service:
- REST API endpoints (`/scan`, `/results`)
- Async job processing (Celery/Redis)
- Rate limiting (per IP/API key)
- OpenAPI documentation
- Docker containerization

### 12. Advanced Features 🎓
**Status**: Planned

- Technology version EOL warnings
- Security vulnerability checks (CVE lookup)
- Performance recommendations
- SEO analysis integration
- WCAG accessibility checks

## Quick Wins

### 13. Documentation Improvements 📚
**Status**: Not Started

- Add animated GIF demo to README
- Create CONTRIBUTING.md guide
- Add architecture diagrams (Mermaid)
- Video walkthrough/tutorial
- API documentation with examples

### 14. Project Cleanup 🧹
**Status**: Not Started

- Add pre-commit hooks (black, ruff, mypy)
- Set up dependabot for dependency updates
- Add issue templates (.github/ISSUE_TEMPLATE/)
- Create PR template
- Add LICENSE file (MIT/Apache)

## Current Focus

**Next Up**: Performance Optimization (#2) + Version Detection Enhancement (#3)

1. **Performance**: Fix slow scan issues, add timeouts, implement caching
2. **Version Detection**: Add version extraction patterns to rules and analyzers
