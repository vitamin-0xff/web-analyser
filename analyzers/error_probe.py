"""Error message analyzer for detecting technologies from error responses."""
from typing import List, Optional, Dict
import logging
import re
from core.context import ScanContext
from models.detection import Detection, Evidence
from models.technology import Technology
from core.analyzer_registry import AnalyzerRegistry, filter_by_rule_types
from fetch.http_client import fetch_url

logger = logging.getLogger(__name__)

# Paths to trigger errors
ERROR_PATHS = [
    "/api/nonexistent",
    "/nonexistent.php",
    "/nonexistent.asp",
    "/nonexistent.aspx",
    "/nonexistent.jsp",
    "/test/error",
    "/.env",
    "/config.php",
    "/admin/config",
]

# Query parameters that might trigger errors
ERROR_PARAMS = [
    "?id=999999",
    "?debug=true",
    "?error=1",
    "?test=invalid",
]


@AnalyzerRegistry.register(
    "error_probe",
    lambda rules: filter_by_rule_types(rules, {"error_message", "error_header", "error_page"})
)
class ErrorProbeAnalyzer:
    """Active analyzer that triggers errors to detect technologies from error messages."""
    
    def __init__(self, rules: List[Technology]):
        self.rules = rules

    async def analyze(self, context: ScanContext) -> List[Detection]:
        """
        Trigger errors and analyze error messages for technology fingerprints.
        
        This is an ACTIVE analyzer - it makes additional HTTP requests.
        """
        detections: List[Detection] = []
        base_url = context.url.rstrip('/')
        
        # Try error-triggering paths
        test_urls = []
        
        # Add invalid paths
        for path in ERROR_PATHS:
            test_urls.append(f"{base_url}{path}")
        
        # Add query parameters to base URL
        for param in ERROR_PARAMS:
            test_urls.append(f"{base_url}/{param}")
        
        for test_url in test_urls[:10]:  # Limit to 10 probes
            try:
                response = await fetch_url(test_url, timeout=5)
                
                # Analyze error responses (4xx, 5xx status codes)
                if response.status_code >= 400:
                    logger.debug(f"Error response from {test_url}: {response.status_code}")
                    
                    response_data = {
                        'body': response.text,
                        'headers': {k.lower(): v for k, v in response.headers.items()},
                        'status': response.status_code
                    }
                    
                    # Match against rules
                    for tech in self.rules:
                        for rule in tech.evidence_rules:
                            if rule.type == "error_message" and rule.pattern:
                                # Check error message in response body
                                if self._match_pattern(rule.pattern, response_data['body']):
                                    # Extract snippet of error message
                                    snippet = self._extract_snippet(rule.pattern, response_data['body'])
                                    
                                    detections.append(
                                        Detection(
                                            name=tech.name,
                                            category=tech.category,
                                            confidence=rule.confidence,
                                            evidence=Evidence(
                                                type="error_message",
                                                value=snippet or "Error page detected",
                                                pattern=rule.pattern
                                            ),
                                            version=self._extract_version(response_data['body'], tech.name)
                                        )
                                    )
                            
                            elif rule.type == "error_header" and rule.name:
                                # Check error headers
                                header_name = rule.name.lower()
                                if header_name in response_data['headers']:
                                    header_value = response_data['headers'][header_name]
                                    if rule.pattern and self._match_pattern(rule.pattern, header_value):
                                        detections.append(
                                            Detection(
                                                name=tech.name,
                                                category=tech.category,
                                                confidence=rule.confidence,
                                                evidence=Evidence(
                                                    type="error_header",
                                                    name=rule.name,
                                                    value=header_value,
                                                    pattern=rule.pattern
                                                ),
                                                version=self._extract_version(header_value, tech.name)
                                            )
                                        )
                            
                            elif rule.type == "error_page":
                                # Check for specific error page patterns
                                if rule.pattern and self._match_pattern(rule.pattern, response_data['body']):
                                    detections.append(
                                        Detection(
                                            name=tech.name,
                                            category=tech.category,
                                            confidence=rule.confidence,
                                            evidence=Evidence(
                                                type="error_page",
                                                value=f"Error page pattern found (status: {response.status_code})"
                                            ),
                                            version=tech.version
                                        )
                                    )
            
            except Exception as e:
                logger.debug(f"Error probe failed for {test_url}: {e}")
                continue
        
        return detections

    def _match_pattern(self, pattern: str, text: str) -> bool:
        """Check if pattern matches text (case-insensitive)."""
        try:
            return bool(re.search(pattern, text, re.IGNORECASE | re.DOTALL))
        except Exception:
            return pattern.lower() in text.lower()

    def _extract_snippet(self, pattern: str, text: str, max_length: int = 100) -> Optional[str]:
        """Extract a snippet of text around the pattern match."""
        try:
            match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
            if match:
                start = max(0, match.start() - 20)
                end = min(len(text), match.end() + 80)
                snippet = text[start:end].strip()
                # Clean up whitespace
                snippet = re.sub(r'\s+', ' ', snippet)
                if len(snippet) > max_length:
                    snippet = snippet[:max_length] + "..."
                return snippet
        except Exception:
            pass
        return None

    def _extract_version(self, text: str, tech_name: str) -> Optional[str]:
        """Try to extract version from error message."""
        version_patterns = [
            rf'{tech_name}[\/\s]+v?(\d+\.\d+(?:\.\d+)?)',
            r'version["\s:]+v?(\d+\.\d+(?:\.\d+)?)',
            r'v(\d+\.\d+(?:\.\d+)?)',
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
