"""Security headers analyzer for detecting missing or misconfigured security headers.

This analyzer checks for:
- Missing security headers (CSP, HSTS, X-Frame-Options, etc.)
- Weak or permissive Content Security Policy
- Missing cookie security attributes (Secure, HttpOnly, SameSite)
- Insecure CORS configurations
- Information disclosure headers
"""
from typing import List
import re
import logging
from core.context import ScanContext
from models.detection import Detection, Evidence
from models.technology import Technology
from core.analyzer_registry import AnalyzerRegistry, filter_by_rule_types


@AnalyzerRegistry.register(
    "security_headers",
    lambda rules: filter_by_rule_types(rules, {"security_header", "security_cookie", "security_csp"})
)
class SecurityHeadersAnalyzer:
    """Analyzes HTTP headers and cookies for security issues."""
    
    # Security headers that should be present
    RECOMMENDED_HEADERS = {
        'strict-transport-security': {
            'name': 'HSTS (HTTP Strict Transport Security)',
            'severity': 'high',
            'description': 'Forces HTTPS connections and prevents protocol downgrade attacks'
        },
        'content-security-policy': {
            'name': 'Content Security Policy (CSP)',
            'severity': 'high',
            'description': 'Prevents XSS and other injection attacks by controlling resource loading'
        },
        'x-frame-options': {
            'name': 'X-Frame-Options',
            'severity': 'medium',
            'description': 'Prevents clickjacking attacks by controlling iframe embedding'
        },
        'x-content-type-options': {
            'name': 'X-Content-Type-Options',
            'severity': 'medium',
            'description': 'Prevents MIME-sniffing attacks'
        },
        'referrer-policy': {
            'name': 'Referrer-Policy',
            'severity': 'low',
            'description': 'Controls referrer information sent with requests'
        },
        'permissions-policy': {
            'name': 'Permissions-Policy',
            'severity': 'low',
            'description': 'Controls browser features and APIs available to the page'
        },
        'x-xss-protection': {
            'name': 'X-XSS-Protection',
            'severity': 'low',
            'description': 'Legacy XSS protection (deprecated but still useful for old browsers)'
        }
    }
    
    # Headers that may leak information
    INFORMATION_DISCLOSURE_HEADERS = {
        'server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version',
        'x-generator', 'x-drupal-cache', 'x-varnish', 'via'
    }
    
    def __init__(self, rules: List[Technology]):
        self.rules = rules
        self.logger = logging.getLogger(__name__)
    
    async def analyze(self, context: ScanContext) -> List[Detection]:
        """Analyze security headers and cookies."""
        detections: List[Detection] = []
        
        # Check for missing security headers
        detections.extend(self._check_missing_headers(context))
        
        # Check Content Security Policy
        detections.extend(self._check_csp(context))
        
        # Check HSTS configuration
        detections.extend(self._check_hsts(context))
        
        # Check cookie security
        detections.extend(self._check_cookie_security(context))
        
        # Check for information disclosure
        detections.extend(self._check_information_disclosure(context))
        
        # Check CORS configuration
        detections.extend(self._check_cors(context))
        
        # Check rules-based detections
        detections.extend(self._check_rules(context))
        
        self.logger.info(f"SecurityHeadersAnalyzer: found {len(detections)} security issues")
        return detections
    
    def _check_missing_headers(self, context: ScanContext) -> List[Detection]:
        """Check for missing security headers."""
        detections = []
        
        for header, info in self.RECOMMENDED_HEADERS.items():
            if header not in context.headers:
                confidence = 0.95 if info['severity'] == 'high' else 0.85 if info['severity'] == 'medium' else 0.75
                detections.append(Detection(
                    name=f"Missing {info['name']}",
                    category="Security",
                    confidence=confidence,
                    evidence=Evidence(
                        type="security_header",
                        name=header,
                        value="missing",
                        pattern=info['description']
                    ),
                    version=None
                ))
        
        return detections
    
    def _check_csp(self, context: ScanContext) -> List[Detection]:
        """Analyze Content Security Policy for weaknesses."""
        detections = []
        csp = context.headers.get('content-security-policy', '')
        
        if not csp:
            return []
        
        # Check for unsafe directives
        unsafe_patterns = [
            (r"'unsafe-inline'", "Allows inline scripts/styles (XSS risk)"),
            (r"'unsafe-eval'", "Allows eval() (XSS risk)"),
            (r"\*", "Wildcard source allows any domain"),
            (r"data:", "Data URIs can be exploited"),
            (r"https?://", "HTTP sources in HTTPS page (mixed content risk)")
        ]
        
        for pattern, description in unsafe_patterns:
            if re.search(pattern, csp, re.IGNORECASE):
                detections.append(Detection(
                    name="Weak Content Security Policy",
                    category="Security",
                    confidence=0.90,
                    evidence=Evidence(
                        type="security_csp",
                        name="content-security-policy",
                        value=csp[:200],  # Truncate long CSP
                        pattern=f"Contains {description}"
                    ),
                    version=None
                ))
        
        return detections
    
    def _check_hsts(self, context: ScanContext) -> List[Detection]:
        """Check HSTS configuration."""
        detections = []
        hsts = context.headers.get('strict-transport-security', '')
        
        if not hsts:
            return []
        
        # Extract max-age
        max_age_match = re.search(r'max-age=(\d+)', hsts, re.IGNORECASE)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            
            # Warn if max-age is too short (less than 6 months)
            if max_age < 15552000:  # 6 months in seconds
                detections.append(Detection(
                    name="Weak HSTS Configuration",
                    category="Security",
                    confidence=0.85,
                    evidence=Evidence(
                        type="security_header",
                        name="strict-transport-security",
                        value=hsts,
                        pattern=f"max-age={max_age} is less than 6 months (recommended: 31536000)"
                    ),
                    version=None
                ))
        
        # Check for includeSubDomains
        if 'includesubdomains' not in hsts.lower():
            detections.append(Detection(
                name="HSTS Missing includeSubDomains",
                category="Security",
                confidence=0.75,
                evidence=Evidence(
                    type="security_header",
                    name="strict-transport-security",
                    value=hsts,
                    pattern="Missing includeSubDomains directive"
                ),
                version=None
            ))
        
        return detections
    
    def _check_cookie_security(self, context: ScanContext) -> List[Detection]:
        """Check cookies for security attributes."""
        detections = []
        
        for cookie_name, cookie_value in context.cookies.items():
            # Note: Cookie attributes (Secure, HttpOnly, SameSite) are typically in Set-Cookie header
            # which we don't have direct access to. We check set-cookie header if available.
            pass
        
        # Check set-cookie headers for missing flags
        set_cookie_header = context.headers.get('set-cookie', '')
        if set_cookie_header:
            issues = []
            
            if 'secure' not in set_cookie_header.lower():
                issues.append("Missing Secure flag")
            
            if 'httponly' not in set_cookie_header.lower():
                issues.append("Missing HttpOnly flag")
            
            if 'samesite' not in set_cookie_header.lower():
                issues.append("Missing SameSite attribute")
            elif re.search(r'samesite=none', set_cookie_header, re.IGNORECASE):
                issues.append("SameSite=None (allows cross-site requests)")
            
            if issues:
                detections.append(Detection(
                    name="Insecure Cookie Configuration",
                    category="Security",
                    confidence=0.85,
                    evidence=Evidence(
                        type="security_cookie",
                        name="set-cookie",
                        value=set_cookie_header[:200],
                        pattern="; ".join(issues)
                    ),
                    version=None
                ))
        
        return detections
    
    def _check_information_disclosure(self, context: ScanContext) -> List[Detection]:
        """Check for headers that disclose server information."""
        detections = []
        
        for header in self.INFORMATION_DISCLOSURE_HEADERS:
            if header in context.headers:
                value = context.headers[header]
                detections.append(Detection(
                    name="Information Disclosure in Headers",
                    category="Security",
                    confidence=0.70,
                    evidence=Evidence(
                        type="security_header",
                        name=header,
                        value=value,
                        pattern=f"Header '{header}' reveals server/technology information"
                    ),
                    version=None
                ))
        
        return detections
    
    def _check_cors(self, context: ScanContext) -> List[Detection]:
        """Check CORS configuration for security issues."""
        detections = []
        
        acao = context.headers.get('access-control-allow-origin', '')
        if acao:
            # Check for wildcard CORS
            if acao == '*':
                detections.append(Detection(
                    name="Permissive CORS Policy",
                    category="Security",
                    confidence=0.80,
                    evidence=Evidence(
                        type="security_header",
                        name="access-control-allow-origin",
                        value=acao,
                        pattern="Wildcard (*) allows any origin to make requests"
                    ),
                    version=None
                ))
            
            # Check if credentials are allowed with wildcard (major security issue)
            acac = context.headers.get('access-control-allow-credentials', '')
            if acac.lower() == 'true' and acao == '*':
                detections.append(Detection(
                    name="Critical CORS Misconfiguration",
                    category="Security",
                    confidence=0.95,
                    evidence=Evidence(
                        type="security_header",
                        name="access-control-allow-credentials",
                        value=f"ACAO: {acao}, ACAC: {acac}",
                        pattern="Credentials allowed with wildcard origin (authentication bypass)"
                    ),
                    version=None
                ))
        
        return detections
    
    def _check_rules(self, context: ScanContext) -> List[Detection]:
        """Check rules-based security detections."""
        detections = []
        
        for tech in self.rules:
            for rule in tech.evidence_rules:
                if rule.type == "security_header":
                    header_name = rule.name
                    if not header_name:
                        continue
                    
                    header_value = context.headers.get(header_name.lower())
                    if header_value and rule.pattern:
                        if re.search(rule.pattern, header_value, re.IGNORECASE):
                            detections.append(Detection(
                                name=tech.name,
                                category=tech.category,
                                confidence=rule.confidence,
                                evidence=Evidence(
                                    type="security_header",
                                    name=header_name,
                                    value=header_value,
                                    pattern=rule.pattern
                                ),
                                version=tech.version
                            ))
        
        return detections
