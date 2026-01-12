from typing import List
import re
from core.context import ScanContext
from models.detection import Detection, Evidence
from models.technology import Technology

class CookiesAnalyzer:
    def __init__(self, rules: List[Technology]):
        self.rules = rules

    async def analyze(self, context: ScanContext) -> List[Detection]:
        detections: List[Detection] = []
        cookie_names = context.cookies.keys()

        for tech in self.rules:
            for rule in tech.evidence_rules:
                if rule.type != "cookie":
                    continue

                # Check by cookie name
                if rule.name:
                    if rule.name in cookie_names:
                        detections.append(
                            Detection(
                                name=tech.name,
                                category=tech.category,
                                confidence=rule.confidence,
                                evidence=Evidence(type="cookie", name=rule.name, value=context.cookies[rule.name]),
                                version=tech.version
                            )
                        )
                
                # Check by pattern against cookie names
                elif rule.pattern:
                    for cookie_name in cookie_names:
                        if re.search(rule.pattern, cookie_name, re.IGNORECASE):
                            detections.append(
                                Detection(
                                    name=tech.name,
                                    category=tech.category,
                                    confidence=rule.confidence,
                                    evidence=Evidence(type="cookie", name=cookie_name, pattern=rule.pattern),
                                    version=tech.version
                                )
                            )
                
        return detections
