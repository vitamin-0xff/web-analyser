from typing import List
import re
from core.context import ScanContext
from models.detection import Detection, Evidence
from models.technology import Technology


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
                                version=tech.version
                            )
                        )
                
                elif rule.type == "meta_property":
                    # Match <meta property="..." content="...">
                    pattern = f'<meta\\s+property=["\']?{re.escape(rule.name or "")}["\']?\\s+content=["\']([^"\']+)["\']'
                    match = re.search(pattern, html, re.IGNORECASE)
                    if match and rule.pattern and re.search(rule.pattern, match.group(1), re.IGNORECASE):
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
                                version=tech.version
                            )
                        )
        
        return detections
