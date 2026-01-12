from typing import List
import re
from core.context import ScanContext
from models.detection import Detection, Evidence
from models.technology import Technology
from core.analyzer_registry import AnalyzerRegistry, filter_by_rule_types


@AnalyzerRegistry.register("pwa", lambda rules: filter_by_rule_types(rules, {"pwa_manifest", "service_worker"}))
class PWAAnalyzer:
    """Analyze Progressive Web App manifest and service worker usage."""
    
    def __init__(self, rules: List[Technology]):
        self.rules = rules

    async def analyze(self, context: ScanContext) -> List[Detection]:
        detections: List[Detection] = []
        
        # Check for manifest presence
        has_manifest = bool(context.manifest_url)
        
        # Check for service worker
        has_service_worker = bool(context.service_worker_url)
        
        # Check for manifest-related script patterns
        has_pwa_patterns = bool(
            re.search(r'navigator\.serviceWorker|\/sw\.js|serviceWorker\.register', context.html, re.IGNORECASE)
        )
        
        for tech in self.rules:
            for rule in tech.evidence_rules:
                if rule.type == "pwa_manifest" and (has_manifest or has_pwa_patterns):
                    detections.append(
                        Detection(
                            name=tech.name,
                            category=tech.category,
                            confidence=rule.confidence,
                            evidence=Evidence(
                                type="pwa_manifest",
                                value=context.manifest_url or "inferred"
                            ),
                            version=tech.version
                        )
                    )
                
                elif rule.type == "service_worker" and has_service_worker:
                    detections.append(
                        Detection(
                            name=tech.name,
                            category=tech.category,
                            confidence=rule.confidence,
                            evidence=Evidence(
                                type="service_worker",
                                value=context.service_worker_url or "inferred"
                            ),
                            version=tech.version
                        )
                    )
        
        return detections
