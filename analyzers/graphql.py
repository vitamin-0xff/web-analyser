"""GraphQL introspection analyzer for detecting GraphQL servers and their technologies."""
from typing import List, Optional
import logging
from core.context import ScanContext
from models.detection import Detection, Evidence
from models.technology import Technology
from core.analyzer_registry import AnalyzerRegistry, filter_by_rule_types
from fetch.http_client import fetch_url

logger = logging.getLogger(__name__)

# Common GraphQL endpoint paths
GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/query",
    "/api/query",
    "/gql",
    "/api/gql",
    "/graphql/v1",
    "/api/v1/graphql",
]

# GraphQL introspection query to detect server
INTROSPECTION_QUERY = """
{
  __schema {
    queryType {
      name
    }
    mutationType {
      name
    }
    subscriptionType {
      name
    }
  }
}
"""

# Simple query to test GraphQL endpoint
SIMPLE_QUERY = '{"query": "{ __typename }"}'


@AnalyzerRegistry.register(
    "graphql",
    lambda rules: filter_by_rule_types(rules, {"graphql_introspection", "graphql_header"})
)
class GraphQLAnalyzer:
    """Active analyzer that probes for GraphQL endpoints and introspects schemas."""
    
    def __init__(self, rules: List[Technology]):
        self.rules = rules

    async def analyze(self, context: ScanContext) -> List[Detection]:
        """
        Probe for GraphQL endpoints and detect technologies.
        
        This is an ACTIVE analyzer - it makes additional HTTP requests.
        """
        detections: List[Detection] = []
        base_url = context.url.rstrip('/')
        
        # Try common GraphQL endpoint paths
        for path in GRAPHQL_PATHS:
            endpoint = f"{base_url}{path}"
            
            try:
                # Try POST request with introspection query
                response = await fetch_url(
                    endpoint,
                    method="POST",
                    headers={"Content-Type": "application/json"},
                    data=INTROSPECTION_QUERY,
                    timeout=5
                )
                
                if response.status_code in [200, 400]:  # 400 might mean GraphQL error, still valid
                    # Check if response looks like GraphQL
                    response_text = response.text.lower()
                    
                    if any(indicator in response_text for indicator in ['"data":', '"errors":', '__schema', '__typename']):
                        logger.info(f"GraphQL endpoint detected at {endpoint}")
                        
                        # Match against rules
                        for tech in self.rules:
                            for rule in tech.evidence_rules:
                                if rule.type == "graphql_introspection":
                                    # Check response body for patterns
                                    if rule.pattern and self._match_pattern(rule.pattern, response.text):
                                        detections.append(
                                            Detection(
                                                name=tech.name,
                                                category=tech.category,
                                                confidence=rule.confidence,
                                                evidence=Evidence(
                                                    type="graphql_introspection",
                                                    value=endpoint,
                                                    pattern=rule.pattern
                                                ),
                                                version=self._extract_version(response.text, tech.name)
                                            )
                                        )
                                
                                elif rule.type == "graphql_header":
                                    # Check response headers
                                    headers_lower = {k.lower(): v for k, v in response.headers.items()}
                                    if rule.name and rule.name.lower() in headers_lower:
                                        header_value = headers_lower[rule.name.lower()]
                                        if rule.pattern and self._match_pattern(rule.pattern, header_value):
                                            detections.append(
                                                Detection(
                                                    name=tech.name,
                                                    category=tech.category,
                                                    confidence=rule.confidence,
                                                    evidence=Evidence(
                                                        type="graphql_header",
                                                        name=rule.name,
                                                        value=header_value,
                                                        pattern=rule.pattern
                                                    ),
                                                    version=self._extract_version(header_value, tech.name)
                                                )
                                            )
            
            except Exception as e:
                logger.debug(f"GraphQL probe failed for {endpoint}: {e}")
                continue
        
        return detections

    def _match_pattern(self, pattern: str, text: str) -> bool:
        """Check if pattern matches text (case-insensitive)."""
        import re
        try:
            return bool(re.search(pattern, text, re.IGNORECASE))
        except Exception:
            return pattern.lower() in text.lower()

    def _extract_version(self, text: str, tech_name: str) -> Optional[str]:
        """Try to extract version from response."""
        import re
        
        # Look for version patterns near the tech name
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
