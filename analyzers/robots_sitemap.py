from typing import List
import re
from core.context import ScanContext
from models.detection import Detection, Evidence
from models.technology import Technology


class RobotsSitemapAnalyzer:
    """Analyze robots.txt and sitemap.xml for CMS/framework signatures."""
    
    def __init__(self, rules: List[Technology]):
        self.rules = rules

    async def analyze(self, context: ScanContext) -> List[Detection]:
        detections: List[Detection] = []
        
        robots_txt = context.robots_txt or ""
        sitemaps = context.sitemaps or []
        
        for tech in self.rules:
            for rule in tech.evidence_rules:
                if rule.type == "robots_txt" and robots_txt and rule.pattern:
                    if re.search(rule.pattern, robots_txt, re.IGNORECASE):
                        detections.append(
                            Detection(
                                name=tech.name,
                                category=tech.category,
                                confidence=rule.confidence,
                                evidence=Evidence(
                                    type="robots_txt",
                                    pattern=rule.pattern,
                                    value=robots_txt[:200]
                                ),
                                version=tech.version
                            )
                        )
                
                elif rule.type == "sitemap_pattern" and sitemaps and rule.pattern:
                    if re.search(rule.pattern, ' '.join(sitemaps), re.IGNORECASE):
                        detections.append(
                            Detection(
                                name=tech.name,
                                category=tech.category,
                                confidence=rule.confidence,
                                evidence=Evidence(
                                    type="sitemap_pattern",
                                    pattern=rule.pattern,
                                    value=sitemaps[0] if sitemaps else "inferred"
                                ),
                                version=tech.version
                            )
                        )
        
        return detections
