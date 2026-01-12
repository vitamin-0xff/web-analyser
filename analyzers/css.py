from typing import List, Optional
import re
from core.context import ScanContext
from models.detection import Detection, Evidence
from models.technology import Technology
from core.version_utils import extract_version_from_url

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
                            # Extract version from stylesheet URL
                            version = self._extract_version(stylesheet_url, tech)
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
                                    version=version
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

    def _extract_version(self, stylesheet_url: str, tech: Technology) -> Optional[str]:
        """Extract version from stylesheet URL using technology-specific pattern."""
        # First try the technology-specific pattern if available
        if hasattr(tech, 'version_pattern') and tech.version_pattern:
            match = re.search(tech.version_pattern, stylesheet_url, re.IGNORECASE)
            if match:
                return match.group(1)
        
        # Fallback to generic version extraction with tech name context
        return extract_version_from_url(stylesheet_url, tech.name)
