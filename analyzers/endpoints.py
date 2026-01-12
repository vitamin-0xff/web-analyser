from typing import List
import re
from core.context import ScanContext
from models.detection import Detection, Evidence
from models.technology import Technology


class EndpointsAnalyzer:
    """Analyze API endpoints, GraphQL, OpenAPI references."""
    
    def __init__(self, rules: List[Technology]):
        self.rules = rules

    async def analyze(self, context: ScanContext) -> List[Detection]:
        detections: List[Detection] = []
        
        # Combine all URLs: scripts, stylesheets, and links in HTML
        all_urls = context.scripts + context.stylesheets
        html_links = re.findall(r'href=["\']([^"\']+)["\']', context.html)
        all_urls.extend(html_links)
        urls_text = ' '.join(all_urls)
        
        for tech in self.rules:
            for rule in tech.evidence_rules:
                if rule.type in ["graphql_endpoint", "openapi_url", "api_pattern"] and rule.pattern:
                    if re.search(rule.pattern, urls_text, re.IGNORECASE):
                        detections.append(
                            Detection(
                                name=tech.name,
                                category=tech.category,
                                confidence=rule.confidence,
                                evidence=Evidence(
                                    type=rule.type,
                                    pattern=rule.pattern,
                                    value=urls_text[:150]
                                ),
                                version=tech.version
                            )
                        )
        
        return detections
