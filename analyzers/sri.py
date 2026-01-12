from typing import List
import re
from core.context import ScanContext
from models.detection import Detection, Evidence
from models.technology import Technology
from core.analyzer_registry import AnalyzerRegistry, filter_by_rule_types


@AnalyzerRegistry.register("sri", lambda rules: filter_by_rule_types(rules, {"sri_hash"}))
class SRIAnalyzer:
    """Match Subresource Integrity hashes against known library versions."""
    
    def __init__(self, rules: List[Technology]):
        self.rules = rules

    async def analyze(self, context: ScanContext) -> List[Detection]:
        detections: List[Detection] = []
        html = context.html
        
        # Extract all integrity attributes from script and link tags
        integrity_pattern = r'integrity\s*=\s*["\']([^"\']+)["\']'
        integrity_hashes = re.findall(integrity_pattern, html, re.IGNORECASE)
        
        for tech in self.rules:
            for rule in tech.evidence_rules:
                if rule.type == "sri_hash" and rule.value:
                    # Match any hash in the page
                    for sri_hash in integrity_hashes:
                        if rule.value in sri_hash:
                            detections.append(
                                Detection(
                                    name=tech.name,
                                    category=tech.category,
                                    confidence=rule.confidence,
                                    evidence=Evidence(
                                        type="sri_hash",
                                        value=sri_hash[:100]  # Truncate long hashes
                                    ),
                                    version=tech.version
                                )
                            )
                            break  # Only match once per rule
        
        return detections
