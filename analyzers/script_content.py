from typing import List
import re
from core.context import ScanContext
from models.detection import Detection, Evidence
from models.technology import Technology
from core.analyzer_registry import AnalyzerRegistry, filter_by_rule_types


@AnalyzerRegistry.register("script_content", lambda rules: filter_by_rule_types(rules, {"script_content_pattern", "inline_js_variable"}))
class ScriptContentAnalyzer:
    """Analyze inline script blocks for framework initialization patterns and config objects."""
    
    def __init__(self, rules: List[Technology]):
        self.rules = rules

    async def analyze(self, context: ScanContext) -> List[Detection]:
        detections: List[Detection] = []
        html = context.html
        
        # Extract all inline <script> blocks (without src attribute)
        inline_script_pattern = r'<script(?![^>]*\bsrc\s*=)[^>]*>(.*?)</script>'
        inline_scripts = re.findall(inline_script_pattern, html, re.IGNORECASE | re.DOTALL)
        inline_script_text = '\n'.join(inline_scripts)
        
        for tech in self.rules:
            for rule in tech.evidence_rules:
                if rule.type == "script_content_pattern":
                    pattern_to_match = rule.pattern or rule.value
                    if pattern_to_match and re.search(pattern_to_match, inline_script_text, re.IGNORECASE):
                        detections.append(
                            Detection(
                                name=tech.name,
                                category=tech.category,
                                confidence=rule.confidence,
                                evidence=Evidence(
                                    type="script_content_pattern",
                                    pattern=pattern_to_match,
                                    value=inline_script_text[:200]  # First 200 chars
                                ),
                                version=tech.version
                            )
                        )
                
                elif rule.type == "inline_js_variable":
                    pattern_to_match = rule.pattern or rule.value
                    if pattern_to_match and re.search(pattern_to_match, inline_script_text, re.IGNORECASE):
                        detections.append(
                            Detection(
                                name=tech.name,
                                category=tech.category,
                                confidence=rule.confidence,
                                evidence=Evidence(
                                    type="inline_js_variable",
                                    pattern=pattern_to_match,
                                    value=inline_script_text[:200]
                                ),
                                version=tech.version
                            )
                        )
        
        return detections
