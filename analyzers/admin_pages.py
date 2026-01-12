"""Admin pages analyzer for detecting admin interfaces and backend technologies."""
from typing import List, Optional
import logging
import re
from core.context import ScanContext
from models.detection import Detection, Evidence
from models.technology import Technology
from core.analyzer_registry import AnalyzerRegistry, filter_by_rule_types
from core.endpoints_loader import load_admin_pages
from fetch.http_client import fetch_url

logger = logging.getLogger(__name__)


@AnalyzerRegistry.register(
    "admin_pages",
    lambda rules: filter_by_rule_types(rules, {"admin_page", "admin_interface", "admin_detection"}),
    analyzer_type="active"
)
class AdminPagesAnalyzer:
    """Active analyzer that probes for admin pages and detects backend technologies."""
    
    def __init__(self, rules: List[Technology]):
        self.rules = rules

    async def analyze(self, context: ScanContext) -> List[Detection]:
        """
        Probe for admin pages and detect technologies from their responses.
        
        This is an ACTIVE analyzer - it makes additional HTTP requests.
        """
        detections: List[Detection] = []
        base_url = context.url.rstrip('/')
        
        # Load admin page paths and indicators from configuration
        admin_paths, admin_indicators = load_admin_pages()
        
        # Probe admin pages
        for path in admin_paths:
            endpoint = f"{base_url}{path}"
            
            try:
                # Try GET request with timeout
                response = await fetch_url(endpoint, timeout=5)
                
                # Check response status codes and content
                # 200 = accessible, 401/403 = exists but protected, 301/302 = redirect
                if response.status_code in [200, 301, 302, 401, 403]:
                    logger.debug(f"Admin page detected: {endpoint} (status: {response.status_code})")
                    
                    response_data = {
                        'body': response.text,
                        'headers': {k.lower(): v for k, v in response.headers.items()},
                        'status': response.status_code
                    }
                    
                    # Check for admin page indicators in response
                    is_admin_page = self._is_admin_page(response_data, admin_indicators)
                    
                    if is_admin_page:
                        # Match against rules for technology detection
                        for tech in self.rules:
                            for rule in tech.evidence_rules:
                                if rule.type == "admin_page" and rule.pattern:
                                    # Check admin page content
                                    if self._match_pattern(rule.pattern, response_data['body']):
                                        detections.append(
                                            Detection(
                                                name=tech.name,
                                                category=tech.category,
                                                confidence=rule.confidence,
                                                evidence=Evidence(
                                                    type="admin_page",
                                                    value=endpoint,
                                                    pattern=rule.pattern
                                                ),
                                                version=self._extract_version(response_data['body'], tech.name)
                                            )
                                        )
                                
                                elif rule.type == "admin_interface":
                                    # Check for admin interface indicators
                                    if rule.pattern and self._match_pattern(rule.pattern, response_data['body']):
                                        detections.append(
                                            Detection(
                                                name=tech.name,
                                                category=tech.category,
                                                confidence=rule.confidence,
                                                evidence=Evidence(
                                                    type="admin_interface",
                                                    value=endpoint,
                                                    pattern=rule.pattern
                                                ),
                                                version=self._extract_version(response_data['body'], tech.name)
                                            )
                                        )
                                
                                elif rule.type == "admin_detection":
                                    # Check for any admin-related patterns
                                    if rule.pattern and self._match_pattern(rule.pattern, response_data['body']):
                                        detections.append(
                                            Detection(
                                                name=tech.name,
                                                category=tech.category,
                                                confidence=rule.confidence,
                                                evidence=Evidence(
                                                    type="admin_detection",
                                                    value=endpoint
                                                ),
                                                version=tech.version
                                            )
                                        )
                    
                    # Also check headers for technology hints
                    headers_lower = {k.lower(): v for k, v in response.headers.items()}
                    for tech in self.rules:
                        for rule in tech.evidence_rules:
                            if rule.type == "header" and rule.name:
                                header_name = rule.name.lower()
                                if header_name in headers_lower:
                                    header_value = headers_lower[header_name]
                                    if rule.pattern and self._match_pattern(rule.pattern, header_value):
                                        detections.append(
                                            Detection(
                                                name=tech.name,
                                                category=tech.category,
                                                confidence=rule.confidence,
                                                evidence=Evidence(
                                                    type="header",
                                                    name=rule.name,
                                                    value=header_value,
                                                    pattern=rule.pattern
                                                ),
                                                version=self._extract_version(header_value, tech.name)
                                            )
                                        )
            
            except Exception as e:
                logger.debug(f"Admin page probe failed for {endpoint}: {e}")
                continue
        
        return detections

    def _is_admin_page(self, response_data: dict, admin_indicators: List[str]) -> bool:
        """
        Check if response indicates an admin page.
        
        Args:
            response_data: Dictionary with 'body', 'headers', 'status'
            admin_indicators: List of text patterns to look for
            
        Returns:
            True if response looks like an admin page
        """
        # Status code 401/403 is strong indicator of admin page
        if response_data['status'] in [401, 403]:
            return True
        
        # Check for admin indicators in response body
        body_lower = response_data['body'].lower()
        
        for indicator in admin_indicators:
            if indicator.lower() in body_lower:
                return True
        
        return False

    def _match_pattern(self, pattern: str, text: str) -> bool:
        """Check if pattern matches text (case-insensitive)."""
        try:
            return bool(re.search(pattern, text, re.IGNORECASE))
        except Exception:
            return pattern.lower() in text.lower()

    def _extract_version(self, text: str, tech_name: str) -> Optional[str]:
        """Try to extract version from response."""
        version_patterns = [
            rf'{tech_name}[\/\s]+v?(\d+\.\d+(?:\.\d+)?)',
            r'"version"["\s:]+v?"?(\d+\.\d+(?:\.\d+)?)"?',
            r'version["\s:]+v?(\d+\.\d+(?:\.\d+)?)',
            r'v(\d+\.\d+(?:\.\d+)?)',
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
