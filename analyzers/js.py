from typing import List, Optional
import re
from core.context import ScanContext
from models.detection import Detection, Evidence
from models.technology import Technology
from core.version_utils import extract_version_from_url

class JsAnalyzer:
    def __init__(self, rules: List[Technology]):
        self.rules = rules

    async def analyze(self, context: ScanContext) -> List[Detection]:
        detections: List[Detection] = []

        for tech in self.rules:
            for rule in tech.evidence_rules:
                if rule.type not in ["script_src", "js_global"]:
                    continue

                # Analyze script URLs
                if rule.type == "script_src" and rule.pattern:
                    for script_url in context.scripts:
                        if re.search(rule.pattern, script_url, re.IGNORECASE):
                            # Extract version from script URL
                            version = self._extract_version(script_url, tech)
                            detections.append(
                                Detection(
                                    name=tech.name,
                                    category=tech.category,
                                    confidence=rule.confidence,
                                    evidence=Evidence(
                                        type="script_src",
                                        value=script_url,
                                        pattern=rule.pattern
                                    ),
                                    version=version
                                )
                            )
                
                # Analyze JS globals
                elif rule.type == "js_global" and rule.pattern:
                    # Check if the pattern (regex for global name) matches any of the extracted globals
                    for js_global in context.js_globals:
                        if re.search(rule.pattern, js_global, re.IGNORECASE):
                            detections.append(
                                Detection(
                                    name=tech.name,
                                    category=tech.category,
                                    confidence=rule.confidence,
                                    evidence=Evidence(
                                        type="js_global",
                                        value=js_global,
                                        pattern=rule.pattern
                                    ),
                                    version=tech.version
                                )
                            )

        # Deduplicate detections to avoid multiple hits for the same tech
        return self._deduplicate(detections)

    def _extract_version(self, script_url: str, tech: Technology) -> Optional[str]:
        """Extract version from script URL using technology-specific pattern."""
        # First try the technology-specific pattern if available
        if hasattr(tech, 'version_pattern') and tech.version_pattern:
            match = re.search(tech.version_pattern, script_url, re.IGNORECASE)
            if match:
                return match.group(1)
        
        # Fallback to generic version extraction with tech name context
        return extract_version_from_url(script_url, tech.name)

    def _deduplicate(self, detections: List[Detection]) -> List[Detection]:
        """Keeps only the highest-confidence detection for each technology name."""
        best_detections = {}
        for detection in detections:
            if detection.name not in best_detections or \
               detection.confidence > best_detections[detection.name].confidence:
                best_detections[detection.name] = detection
        return list(best_detections.values())
