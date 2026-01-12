from typing import List
import re
from core.context import ScanContext
from models.detection import Detection, Evidence
from models.technology import Technology
from core.analyzer_registry import AnalyzerRegistry, filter_by_rule_types


@AnalyzerRegistry.register("forms", lambda rules: filter_by_rule_types(rules, {"form_action_pattern", "hidden_field_name"}))
class FormsAnalyzer:
    """Detect technologies via form attributes, action URLs, and hidden field names."""
    
    def __init__(self, rules: List[Technology]):
        self.rules = rules

    async def analyze(self, context: ScanContext) -> List[Detection]:
        detections: List[Detection] = []
        html = context.html
        
        # Extract all forms with their attributes
        form_pattern = r'<form([^>]*)>(.*?)</form>'
        forms = re.findall(form_pattern, html, re.IGNORECASE | re.DOTALL)
        
        for form_attrs, form_content in forms:
            # Extract action attribute
            action_match = re.search(r'action\s*=\s*["\']([^"\']+)["\']', form_attrs, re.IGNORECASE)
            action_url = action_match.group(1) if action_match else ""
            
            # Extract hidden input fields
            hidden_fields = re.findall(r'<input[^>]*type\s*=\s*["\']hidden["\'][^>]*name\s*=\s*["\']([^"\']+)["\']', 
                                       form_content, re.IGNORECASE)
            
            for tech in self.rules:
                for rule in tech.evidence_rules:
                    if rule.type == "form_action_pattern" and rule.pattern:
                        if re.search(rule.pattern, action_url, re.IGNORECASE):
                            detections.append(
                                Detection(
                                    name=tech.name,
                                    category=tech.category,
                                    confidence=rule.confidence,
                                    evidence=Evidence(
                                        type="form_action_pattern",
                                        pattern=rule.pattern,
                                        value=action_url
                                    ),
                                    version=tech.version
                                )
                            )
                    
                    elif rule.type == "hidden_field_name" and rule.value:
                        if rule.value in hidden_fields:
                            detections.append(
                                Detection(
                                    name=tech.name,
                                    category=tech.category,
                                    confidence=rule.confidence,
                                    evidence=Evidence(
                                        type="hidden_field_name",
                                        name=rule.value,
                                        value=rule.value
                                    ),
                                    version=tech.version
                                )
                            )
        
        return detections
