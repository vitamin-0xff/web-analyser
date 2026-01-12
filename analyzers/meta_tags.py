from typing import List, Optional
import re
from core.context import ScanContext
from models.detection import Detection, Evidence
from models.technology import Technology
from core.version_utils import extract_version_from_meta_tag
from core.analyzer_registry import AnalyzerRegistry, filter_by_rule_types


@AnalyzerRegistry.register(
    "meta_tags",
    lambda rules: filter_by_rule_types(rules, {"meta_name", "meta_property"})
)
class MetaTagsAnalyzer:
    """Analyze meta tags for CMS/framework signatures."""
    
    def __init__(self, rules: List[Technology]):
        self.rules = rules

    async def analyze(self, context: ScanContext) -> List[Detection]:
        detections: List[Detection] = []
        html = context.html
        
        for tech in self.rules:
            for rule in tech.evidence_rules:
                if rule.type == "meta_name":
                    # Match <meta name="..." content="...">
                    pattern = f'<meta\\s+name=["\']?{re.escape(rule.name or "")}["\']?\\s+content=["\']([^"\']+)["\']'
                    match = re.search(pattern, html, re.IGNORECASE)
                    if match and rule.pattern and re.search(rule.pattern, match.group(1), re.IGNORECASE):
                        # Extract version from meta tag content
                        version = self._extract_version(match.group(1), tech, rule.name)
                        detections.append(
                            Detection(
                                name=tech.name,
                                category=tech.category,
                                confidence=rule.confidence,
                                evidence=Evidence(
                                    type="meta_name",
                                    name=rule.name,
                                    value=match.group(1),
                                    pattern=rule.pattern
                                ),
                                version=version
                            )
                        )
                
                elif rule.type == "meta_property":
                    # Match <meta property="..." content="...">
                    pattern = f'<meta\\s+property=["\']?{re.escape(rule.name or "")}["\']?\\s+content=["\']([^"\']+)["\']'
                    match = re.search(pattern, html, re.IGNORECASE)
                    if match and rule.pattern and re.search(rule.pattern, match.group(1), re.IGNORECASE):
                        # Extract version from meta tag content
                        version = self._extract_version(match.group(1), tech, rule.name)
                        detections.append(
                            Detection(
                                name=tech.name,
                                category=tech.category,
                                confidence=rule.confidence,
                                evidence=Evidence(
                                    type="meta_property",
                                    name=rule.name,
                                    value=match.group(1),
                                    pattern=rule.pattern
                                ),
                                version=version
                            )
                        )
        
        return detections

    def _extract_version(self, meta_content: str, tech: Technology, meta_name: Optional[str] = None) -> Optional[str]:
        """Extract version from meta tag content using CMS-specific patterns."""
        # Use the meta tag extraction utility which handles WordPress, Drupal, etc.
        return extract_version_from_meta_tag(meta_content, tech.name, meta_name)
