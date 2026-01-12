"""API probing analyzer for detecting REST APIs, versions, and documentation."""
from typing import List, Optional, Dict
import logging
import re
from core.context import ScanContext
from models.detection import Detection, Evidence
from models.technology import Technology
from core.analyzer_registry import AnalyzerRegistry, filter_by_rule_types
from fetch.http_client import fetch_url

logger = logging.getLogger(__name__)

# Common API endpoint patterns
API_ENDPOINTS = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/v1",
    "/v2",
    "/v3",
    "/rest",
    "/api/rest",
    "/api/docs",
    "/api/swagger.json",
    "/api/openapi.json",
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/docs",
    "/.well-known/api",
    "/health",
    "/api/health",
    "/status",
    "/api/status",
    "/version",
    "/api/version",
]


@AnalyzerRegistry.register(
    "api_probe",
    lambda rules: filter_by_rule_types(rules, {"api_response", "api_header", "api_endpoint"})
)
class APIProbeAnalyzer:
    """Active analyzer that probes for API endpoints and detects backend technologies."""
    
    def __init__(self, rules: List[Technology]):
        self.rules = rules

    async def analyze(self, context: ScanContext) -> List[Detection]:
        """
        Probe for API endpoints and detect technologies.
        
        This is an ACTIVE analyzer - it makes additional HTTP requests.
        """
        detections: List[Detection] = []
        base_url = context.url.rstrip('/')
        
        # Probe API endpoints
        for path in API_ENDPOINTS:
            endpoint = f"{base_url}{path}"
            
            try:
                # Try GET request
                response = await fetch_url(endpoint, timeout=5)
                
                if response.status_code in [200, 201, 401, 403]:  # Valid responses
                    logger.debug(f"API endpoint found: {endpoint} (status: {response.status_code})")
                    
                    # Analyze response
                    response_data = {
                        'body': response.text,
                        'headers': {k.lower(): v for k, v in response.headers.items()},
                        'status': response.status_code
                    }
                    
                    # Match against rules
                    for tech in self.rules:
                        for rule in tech.evidence_rules:
                            if rule.type == "api_response" and rule.pattern:
                                # Check response body
                                if self._match_pattern(rule.pattern, response_data['body']):
                                    detections.append(
                                        Detection(
                                            name=tech.name,
                                            category=tech.category,
                                            confidence=rule.confidence,
                                            evidence=Evidence(
                                                type="api_response",
                                                value=endpoint,
                                                pattern=rule.pattern
                                            ),
                                            version=self._extract_version(response_data['body'], tech.name)
                                        )
                                    )
                            
                            elif rule.type == "api_header" and rule.name:
                                # Check response headers
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
                                                    type="api_header",
                                                    name=rule.name,
                                                    value=header_value,
                                                    pattern=rule.pattern
                                                ),
                                                version=self._extract_version(header_value, tech.name)
                                            )
                                        )
                            
                            elif rule.type == "api_endpoint":
                                # Check if specific endpoint exists
                                if rule.value and rule.value in path:
                                    detections.append(
                                        Detection(
                                            name=tech.name,
                                            category=tech.category,
                                            confidence=rule.confidence,
                                            evidence=Evidence(
                                                type="api_endpoint",
                                                value=endpoint
                                            ),
                                            version=tech.version
                                        )
                                    )
            
            except Exception as e:
                logger.debug(f"API probe failed for {endpoint}: {e}")
                continue
        
        return detections

    def _match_pattern(self, pattern: str, text: str) -> bool:
        """Check if pattern matches text (case-insensitive)."""
        try:
            return bool(re.search(pattern, text, re.IGNORECASE))
        except Exception:
            return pattern.lower() in text.lower()

    def _extract_version(self, text: str, tech_name: str) -> Optional[str]:
        """Try to extract version from response."""
        # Look for version patterns
        version_patterns = [
            rf'{tech_name}[\/\s]+v?(\d+\.\d+(?:\.\d+)?)',
            r'"version"["\s:]+v?"?(\d+\.\d+(?:\.\d+)?)"?',
            r'"v"["\s:]+v?"?(\d+\.\d+(?:\.\d+)?)"?',
            r'version["\s:]+v?(\d+\.\d+(?:\.\d+)?)',
            r'v(\d+\.\d+(?:\.\d+)?)',
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
