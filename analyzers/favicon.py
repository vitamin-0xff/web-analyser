from typing import List
from core.context import ScanContext
from models.detection import Detection, Evidence
from models.technology import Technology
from core.analyzer_registry import AnalyzerRegistry, filter_by_rule_types


@AnalyzerRegistry.register("favicon", lambda rules: filter_by_rule_types(rules, {"favicon_hash"}))
class FaviconAnalyzer:
    """Match favicon hash against known technology signatures."""
    
    def __init__(self, rules: List[Technology]):
        self.rules = rules

    async def analyze(self, context: ScanContext) -> List[Detection]:
        detections: List[Detection] = []
        
        if not context.favicon_hash:
            return detections
        
        for tech in self.rules:
            for rule in tech.evidence_rules:
                if rule.type == "favicon_hash" and rule.value:
                    # Exact match on hash
                    if rule.value.lower() == context.favicon_hash.lower():
                        detections.append(
                            Detection(
                                name=tech.name,
                                category=tech.category,
                                confidence=rule.confidence,
                                evidence=Evidence(
                                    type="favicon_hash",
                                    value=context.favicon_hash
                                ),
                                version=tech.version
                            )
                        )
        
        return detections
