from typing import List
import re
import logging
from core.context import ScanContext
from models.detection import Detection, Evidence
from models.technology import Technology

class HeadersAnalyzer:
    def __init__(self, rules: List[Technology]):
        self.rules = rules

    async def analyze(self, context: ScanContext) -> List[Detection]:
        logger = logging.getLogger(__name__)
        detections: List[Detection] = []
        match_count = 0

        for tech in self.rules:
            for rule in tech.evidence_rules:
                if rule.type != "header":
                    continue

                header_name = rule.name
                if not header_name:
                    continue

                header_value = context.headers.get(header_name.lower())
                if not header_value:
                    continue

                # Check pattern if provided
                if rule.pattern:
                    if re.search(rule.pattern, header_value, re.IGNORECASE):
                        logger.debug(f"HeadersAnalyzer matched {tech.name} on header {header_name}")
                        match_count += 1
                        detections.append(
                            Detection(
                                name=tech.name,
                                category=tech.category,
                                confidence=rule.confidence,
                                evidence=Evidence(
                                    type="header",
                                    name=header_name,
                                    value=header_value,
                                    pattern=rule.pattern
                                ),
                                version=tech.version # Or extract from pattern match
                            )
                        )
                
                # Check for exact value match if provided
                elif rule.value and rule.value.lower() == header_value.lower():
                     logger.debug(f"HeadersAnalyzer matched {tech.name} on header {header_name} value match")
                     match_count += 1
                     detections.append(
                        Detection(
                            name=tech.name,
                            category=tech.category,
                            confidence=rule.confidence,
                            evidence=Evidence(
                                type="header",
                                name=header_name,
                                value=header_value
                            ),
                            version=tech.version
                        )
                    )

        logger.debug(f"HeadersAnalyzer: {match_count} matches, {len(detections)} detections")
