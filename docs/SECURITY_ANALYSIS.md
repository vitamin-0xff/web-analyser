# Security Headers Analysis Guide

## Overview

The **SecurityHeadersAnalyzer** is a specialized analyzer that examines HTTP security headers, cookie configurations, and CORS policies to identify potential security vulnerabilities and misconfigurations.

## What It Detects

### 1. Missing Security Headers

The analyzer checks for the presence of important security headers:

| Header | Purpose | Severity |
|--------|---------|----------|
| `Strict-Transport-Security` (HSTS) | Forces HTTPS connections | High |
| `Content-Security-Policy` (CSP) | Prevents XSS and injection attacks | High |
| `X-Frame-Options` | Prevents clickjacking | Medium |
| `X-Content-Type-Options` | Prevents MIME-sniffing | Medium |
| `Referrer-Policy` | Controls referrer information | Low |
| `Permissions-Policy` | Controls browser features | Low |

### 2. Weak Security Configurations

#### Content Security Policy (CSP)
- `unsafe-inline` - Allows inline scripts/styles (XSS risk)
- `unsafe-eval` - Allows eval() execution (XSS risk)
- Wildcard sources (`*`) - Allows any domain
- `data:` URIs - Can be exploited
- HTTP sources in HTTPS pages (mixed content)

#### HSTS Configuration
- Short `max-age` values (< 6 months)
- Missing `includeSubDomains` directive
- Missing `preload` directive

### 3. Insecure Cookies

The analyzer checks `Set-Cookie` headers for missing security attributes:
- **Secure flag** - Cookie only sent over HTTPS
- **HttpOnly flag** - Cookie not accessible via JavaScript
- **SameSite attribute** - Prevents CSRF attacks
- **SameSite=None** - Allows cross-site requests (risky)

### 4. Information Disclosure

Detection of headers that reveal server/technology details:
- `Server` - Web server software and version
- `X-Powered-By` - Backend language/framework
- `X-AspNet-Version`, `X-AspNetMvc-Version`
- `X-Generator`, `X-Drupal-Cache`
- `Via`, `X-Varnish` - Proxy/cache information

### 5. CORS Misconfigurations

- Wildcard CORS (`Access-Control-Allow-Origin: *`)
- **CRITICAL**: Wildcard CORS with credentials enabled (authentication bypass)

### 6. Security Technologies

Detects presence of security tools from rules:
- **WAFs**: Cloudflare, AWS WAF, Imperva, Sucuri, ModSecurity, F5 BIG-IP
- **Bot Protection**: reCAPTCHA, hCaptcha, Turnstile
- **Rate Limiting**: Various rate limit header formats
- **SSL Certificates**: Let's Encrypt, DigiCert, Cloudflare, Sectigo

## Usage

### Command Line

```bash
# Scan a website for security issues
python main.py https://example.com

# Filter for security category in results
python main.py https://example.com | jq '.[] | select(.category == "Security")'

# Save security findings to file
python main.py https://example.com --format json > results.json
```

### Programmatic Usage

```python
import asyncio
from core.engine import Engine

async def check_security(url):
    engine = Engine()
    context = await engine.scan_url(url)
    detections = await engine.analyze_context(context)
    
    # Filter security detections
    security_issues = [d for d in detections if d.category == "Security"]
    
    for issue in security_issues:
        print(f"{issue.name}: {issue.confidence:.2f}")
        print(f"  {issue.evidence.pattern}")

asyncio.run(check_security("https://example.com"))
```

### Using the Example Script

```bash
cd examples
python security_scan_example.py
```

This generates a formatted report with findings grouped by severity and exports to JSON.

## Interpreting Results

### Confidence Levels

| Range | Interpretation |
|-------|----------------|
| 0.90 - 1.00 | Critical/High confidence finding |
| 0.80 - 0.89 | High confidence finding |
| 0.70 - 0.79 | Medium confidence finding |
| < 0.70 | Low priority or informational |

### Common Findings

#### "Missing HSTS"
**Issue**: Site doesn't enforce HTTPS connections  
**Risk**: Users can be downgraded to HTTP (man-in-the-middle attacks)  
**Fix**: Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`

#### "Missing Content Security Policy"
**Issue**: No CSP protection against XSS  
**Risk**: Attacker can inject malicious scripts  
**Fix**: Add `Content-Security-Policy: default-src 'self'` (adjust as needed)

#### "Weak CSP with unsafe-inline"
**Issue**: CSP allows inline scripts  
**Risk**: Reduces XSS protection effectiveness  
**Fix**: Remove `'unsafe-inline'`, use nonces or hashes instead

#### "Missing X-Frame-Options"
**Issue**: Page can be embedded in iframes  
**Risk**: Clickjacking attacks  
**Fix**: Add `X-Frame-Options: DENY` or `X-Frame-Options: SAMEORIGIN`

#### "Insecure Cookie Configuration"
**Issue**: Cookies missing security attributes  
**Risk**: Session hijacking, XSS attacks  
**Fix**: Add `Secure; HttpOnly; SameSite=Strict` to Set-Cookie headers

#### "Permissive CORS Policy"
**Issue**: `Access-Control-Allow-Origin: *`  
**Risk**: Any site can make requests to your API  
**Fix**: Specify allowed origins explicitly

#### "Critical CORS Misconfiguration"
**Issue**: Wildcard CORS with credentials  
**Risk**: Any site can make authenticated requests (severe!)  
**Fix**: Never use `*` with `Access-Control-Allow-Credentials: true`

#### "Information Disclosure in Headers"
**Issue**: Headers reveal server/technology details  
**Risk**: Helps attackers identify vulnerabilities  
**Fix**: Remove or obscure `Server`, `X-Powered-By` headers

## Best Practices

### Essential Security Headers

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted-cdn.com; style-src 'self' https://trusted-cdn.com
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

### Secure Cookie Configuration

```http
Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600
```

### CORS Best Practices

```http
# Specific origin (good)
Access-Control-Allow-Origin: https://trusted-site.com

# With credentials (only with specific origin)
Access-Control-Allow-Origin: https://trusted-site.com
Access-Control-Allow-Credentials: true

# Never do this!
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

## Extending the Analyzer

### Adding Custom Security Rules

Edit `rules/security.yaml`:

```yaml
- name: Custom Security Control
  category: Security
  evidence:
    - type: header
      name: x-custom-security-header
      pattern: enabled
      confidence: 0.90
```

### Adding Custom Checks

Extend `analyzers/security_headers.py`:

```python
def _check_custom_security(self, context: ScanContext) -> List[Detection]:
    """Add your custom security checks here."""
    detections = []
    # Your logic
    return detections
```

Then call it in the `analyze()` method:

```python
async def analyze(self, context: ScanContext) -> List[Detection]:
    detections = []
    # ... existing checks ...
    detections.extend(self._check_custom_security(context))
    return detections
```

## Testing

Run the security analyzer tests:

```bash
# Run all security tests
pytest tests/test_security_analyzer.py -v

# Run specific test
pytest tests/test_security_analyzer.py::test_detects_missing_hsts -v

# Run with coverage
pytest tests/test_security_analyzer.py --cov=analyzers.security_headers
```

## Resources

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [Mozilla Observatory](https://observatory.mozilla.org/)
- [SecurityHeaders.com](https://securityheaders.com/)
- [Content Security Policy Reference](https://content-security-policy.com/)
- [HSTS Preload List](https://hstspreload.org/)

## Limitations

1. **Set-Cookie Analysis**: We only see `Set-Cookie` header in responses, not all cookie attributes from the browser's cookie jar
2. **Dynamic Content**: Only analyzes the initial page load, not dynamically loaded content
3. **Context-Dependent**: Some headers are only relevant in specific contexts (e.g., CORS for APIs)
4. **False Positives**: Information disclosure headers may be intentional for debugging/monitoring

## Roadmap

- [ ] Analyze `Set-Cookie` headers from all responses (not just main page)
- [ ] Add CSP parser to evaluate policy effectiveness
- [ ] Check for deprecated/legacy security headers
- [ ] Rate server configuration against security benchmarks
- [ ] Add remediation suggestions in output
- [ ] Support for scanning multiple pages to get full picture
- [ ] Integration with external security scanners
