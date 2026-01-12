from typing import List
import re
from core.context import ScanContext
from models.detection import Detection, Evidence
from models.technology import Technology

class CssAnalyzer:
    def __init__(self, rules: List[Technology]):
        self.rules = rules

    async def analyze(self, context: ScanContext) -> List[Detection]:
        detections: List[Detection] = []

        for tech in self.rules:
            for rule in tech.evidence_rules:
                if rule.type == "css_link" and rule.pattern:
                    for stylesheet_url in context.stylesheets:
                        if re.search(rule.pattern, stylesheet_url, re.IGNORECASE):
                            detections.append(
                                Detection(
                                    name=tech.name,
                                    category=tech.category,
                                    confidence=rule.confidence,
                                    evidence=Evidence(
                                        type="css_link",
                                        value=stylesheet_url,
                                        pattern=rule.pattern
                                    ),
                                    version=tech.version
                                )
                            )
                
                elif rule.type == "html_pattern" and rule.pattern:
                    if re.search(rule.pattern, context.html, re.IGNORECASE):
                         detections.append(
                            Detection(
                                name=tech.name,
                                category=tech.category,
                                confidence=rule.confidence,
                                evidence=Evidence(
                                    type="html_pattern",
                                    pattern=rule.pattern,
                                    value=re.search(rule.pattern, context.html, re.IGNORECASE).group(0)
                                ),
                                version=tech.version
                            )
                        )

        return detections
