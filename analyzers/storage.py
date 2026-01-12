from typing import List
import re
from core.context import ScanContext
from models.detection import Detection, Evidence
from models.technology import Technology


class StorageAnalyzer:
    """Analyze localStorage/sessionStorage key patterns in page content."""
    
    def __init__(self, rules: List[Technology]):
        self.rules = rules

    async def analyze(self, context: ScanContext) -> List[Detection]:
        detections: List[Detection] = []
        
        # Extract localStorage/sessionStorage key patterns from HTML and JS
        storage_pattern = r'(?:localStorage|sessionStorage)\.(?:setItem|getItem)\(["\']([^"\']+)["\']'
        storage_keys = re.findall(storage_pattern, context.html, re.IGNORECASE)
        storage_text = ' '.join(storage_keys)
        
        for tech in self.rules:
            for rule in tech.evidence_rules:
                if rule.type == "js_storage_key" and rule.pattern:
                    if re.search(rule.pattern, storage_text, re.IGNORECASE):
                        detections.append(
                            Detection(
                                name=tech.name,
                                category=tech.category,
                                confidence=rule.confidence,
                                evidence=Evidence(
                                    type="js_storage_key",
                                    pattern=rule.pattern,
                                    value=', '.join(storage_keys[:5])  # First 5 keys
                                ),
                                version=tech.version
                            )
                        )
        
        return detections
