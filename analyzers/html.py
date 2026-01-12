from typing import List
import re
import logging

from core.context import ScanContext
from models.detection import Detection, Evidence
from models.technology import Technology
from core.analyzer_registry import AnalyzerRegistry, filter_by_rule_types
from core.html_utils import search_html_parallel

@AnalyzerRegistry.register(
    "html",
    lambda rules: filter_by_rule_types(rules, {"html_pattern", "html_comment"})
)
class HtmlAnalyzer:
    def __init__(self, rules: List[Technology]):
        self.rules = rules

    async def analyze(self, context: ScanContext) -> List[Detection]:
        logger = logging.getLogger(__name__)
        detections: List[Detection] = []
        html_content = context.html
        match_count = 0

        for tech in self.rules:
            for rule in tech.evidence_rules:
                if rule.type not in ["html_pattern", "html_comment"]:
                    continue

                if rule.pattern:
                    # Use parallel HTML search utility
                    match = await search_html_parallel(
                        rule.pattern,
                        html_content,
                        re.IGNORECASE,
                        tech.name
                    )

                    if match:
                        logger.debug(f"HtmlAnalyzer matched {tech.name} on {rule.type}")
                        match_count += 1
                        detections.append(
                            Detection(
                                name=tech.name,
                                category=tech.category,
                                confidence=rule.confidence,
                                evidence=Evidence(
                                    type=rule.type,
                                    pattern=rule.pattern,
                                    value=match.group(0)
                                ),
                                version=self._extract_version(match.group(0))
                            )
                        )
                # For exact value match in HTML (less common for HTML patterns)
                elif rule.value and rule.value.lower() in scan_html.lower():
                    logger.debug(f"HtmlAnalyzer matched {tech.name} on value {rule.value}")
                    match_count += 1
                    detections.append(
                        Detection(
                            name=tech.name,
                            category=tech.category,
                            confidence=rule.confidence,
                            evidence=Evidence(
                                type=rule.type,
                                value=rule.value
                            ),
                            version=tech.version
                        )
                    )

        logger.debug(f"HtmlAnalyzer: {match_count} matches, {len(detections)} detections")
        return detections

    def _extract_version(self, text: str) -> str | None:
        """Extracts a version number from a string."""
        match = re.search(r'(\d+\.\d+(\.\d+)?)', text)
        return match.group(1) if match else None
