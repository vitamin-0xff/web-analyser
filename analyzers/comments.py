from typing import List
import re
from core.context import ScanContext
from models.detection import Detection, Evidence
from models.technology import Technology


class CommentsAnalyzer:
    """Analyze HTML, CSS, and JavaScript comments for technology signatures."""
    
    def __init__(self, rules: List[Technology]):
        self.rules = rules

    async def analyze(self, context: ScanContext) -> List[Detection]:
        detections: List[Detection] = []
        html = context.html
        
        # Extract HTML comments
        html_comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
        html_comment_text = '\n'.join(html_comments)
        
        # Extract CSS comments from inline <style> tags
        inline_styles = re.findall(r'<style[^>]*>(.*?)</style>', html, re.IGNORECASE | re.DOTALL)
        css_comments = []
        for style_block in inline_styles:
            css_comments.extend(re.findall(r'/\*(.*?)\*/', style_block, re.DOTALL))
        css_comment_text = '\n'.join(css_comments)
        
        # Extract JS comments from inline <script> tags
        inline_scripts = re.findall(r'<script(?![^>]*\bsrc\s*=)[^>]*>(.*?)</script>', html, re.IGNORECASE | re.DOTALL)
        js_comments = []
        for script_block in inline_scripts:
            # Multi-line comments
            js_comments.extend(re.findall(r'/\*(.*?)\*/', script_block, re.DOTALL))
            # Single-line comments
            js_comments.extend(re.findall(r'//(.*)$', script_block, re.MULTILINE))
        js_comment_text = '\n'.join(js_comments)
        
        for tech in self.rules:
            for rule in tech.evidence_rules:
                if rule.type == "html_comment":
                    pattern_to_match = rule.pattern or rule.value
                    if pattern_to_match and re.search(pattern_to_match, html_comment_text, re.IGNORECASE):
                        detections.append(
                            Detection(
                                name=tech.name,
                                category=tech.category,
                                confidence=rule.confidence,
                                evidence=Evidence(
                                    type="html_comment",
                                    pattern=pattern_to_match,
                                    value=html_comment_text[:200]
                                ),
                                version=tech.version
                            )
                        )
                
                elif rule.type == "css_comment":
                    pattern_to_match = rule.pattern or rule.value
                    if pattern_to_match:
                        match = re.search(pattern_to_match, css_comment_text, re.IGNORECASE)
                        if match:
                            detections.append(
                                Detection(
                                    name=tech.name,
                                    category=tech.category,
                                    confidence=rule.confidence,
                                    evidence=Evidence(
                                        type="css_comment",
                                        pattern=pattern_to_match,
                                        value=match.group(0)[:200]
                                    ),
                                    version=tech.version
                                )
                            )
                
                elif rule.type == "js_comment":
                    pattern_to_match = rule.pattern or rule.value
                    if pattern_to_match:
                        match = re.search(pattern_to_match, js_comment_text, re.IGNORECASE)
                        if match:
                            detections.append(
                                Detection(
                                    name=tech.name,
                                    category=tech.category,
                                    confidence=rule.confidence,
                                    evidence=Evidence(
                                        type="js_comment",
                                        pattern=pattern_to_match,
                                        value=match.group(0)[:200]
                                    ),
                                    version=tech.version
                                )
                            )
        
        return detections
