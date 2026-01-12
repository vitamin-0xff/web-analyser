from typing import List
import re
import json
from core.context import ScanContext
from models.detection import Detection, Evidence
from models.technology import Technology
from core.analyzer_registry import AnalyzerRegistry, filter_by_rule_types


@AnalyzerRegistry.register("structured_data", lambda rules: filter_by_rule_types(rules, {"json_ld_pattern"}))
class StructuredDataAnalyzer:
    """Analyze JSON-LD and schema.org structured data."""
    
    def __init__(self, rules: List[Technology]):
        self.rules = rules

    async def analyze(self, context: ScanContext) -> List[Detection]:
        detections: List[Detection] = []
        html = context.html
        
        # Extract all JSON-LD blocks
        json_ld_pattern = r'<script\s+type=["\']application/ld\+json["\']>(.+?)</script>'
        json_ld_blocks = re.findall(json_ld_pattern, html, re.IGNORECASE | re.DOTALL)
        
        json_ld_text = ' '.join(json_ld_blocks)
        
        for tech in self.rules:
            for rule in tech.evidence_rules:
                if rule.type == "json_ld_pattern":
                    if rule.pattern and re.search(rule.pattern, json_ld_text, re.IGNORECASE):
                        detections.append(
                            Detection(
                                name=tech.name,
                                category=tech.category,
                                confidence=rule.confidence,
                                evidence=Evidence(
                                    type="json_ld_pattern",
                                    pattern=rule.pattern,
                                    value=json_ld_text[:200]  # First 200 chars
                                ),
                                version=tech.version
                            )
                        )
        
        return detections
