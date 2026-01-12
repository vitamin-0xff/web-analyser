from typing import List
from core.context import ScanContext
from models.detection import Detection, Evidence
from models.technology import Technology
from core.analyzer_registry import AnalyzerRegistry, filter_by_rule_types


@AnalyzerRegistry.register("http_details", lambda rules: filter_by_rule_types(rules, {"http_version", "server_timing"}))
class HTTPDetailsAnalyzer:
    """Analyze HTTP response metadata for framework/version hints."""
    
    def __init__(self, rules: List[Technology]):
        self.rules = rules

    async def analyze(self, context: ScanContext) -> List[Detection]:
        detections: List[Detection] = []
        
        http_version = context.http_version or ""
        server_timing = context.server_timing or ""
        
        for tech in self.rules:
            for rule in tech.evidence_rules:
                if rule.type == "http_version" and http_version and rule.pattern:
                    if rule.pattern in http_version:
                        detections.append(
                            Detection(
                                name=tech.name,
                                category=tech.category,
                                confidence=rule.confidence,
                                evidence=Evidence(
                                    type="http_version",
                                    value=http_version
                                ),
                                version=tech.version
                            )
                        )
                
                elif rule.type == "server_timing" and server_timing and rule.pattern:
                    detections.append(
                        Detection(
                            name=tech.name,
                            category=tech.category,
                            confidence=rule.confidence,
                            evidence=Evidence(
                                type="server_timing",
                                value=server_timing[:100]
                            ),
                            version=tech.version
                        )
                    )
        
        return detections
