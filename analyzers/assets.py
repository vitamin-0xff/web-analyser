from typing import List
import re
from core.context import ScanContext
from models.detection import Detection, Evidence
from models.technology import Technology


class AssetsAnalyzer:
    """Analyze asset URLs (fonts, icons, images, CDNs) for technology signatures."""
    
    def __init__(self, rules: List[Technology]):
        self.rules = rules

    async def analyze(self, context: ScanContext) -> List[Detection]:
        detections: List[Detection] = []
        html = context.html
        
        # Extract all CSS links
        css_links = context.stylesheets
        css_links_text = ' '.join(css_links)
        
        # Extract font sources from @font-face and inline styles
        font_pattern = r'@font-face[^}]*src:\s*url\(["\']([^"\']+)["\']'
        font_srcs = re.findall(font_pattern, html, re.IGNORECASE | re.DOTALL)
        font_srcs.extend(re.findall(r'font-family[^;]*url\(["\']([^"\']+)["\']', html, re.IGNORECASE))
        font_srcs_text = ' '.join(font_srcs)
        
        # Extract image sources
        image_pattern = r'<img[^>]+src=["\']([^"\']+)["\']'
        image_srcs = re.findall(image_pattern, html, re.IGNORECASE)
        # Also get background images from inline styles
        bg_image_pattern = r'background(?:-image)?:\s*url\(["\']?([^"\')\s]+)["\']?\)'
        image_srcs.extend(re.findall(bg_image_pattern, html, re.IGNORECASE))
        image_srcs_text = ' '.join(image_srcs)
        
        # Combine all asset URLs for script_src patterns
        all_assets = ' '.join(css_links + font_srcs + image_srcs + context.scripts)
        
        for tech in self.rules:
            for rule in tech.evidence_rules:
                pattern_to_match = rule.pattern or rule.value
                if not pattern_to_match:
                    continue
                
                matched = False
                match_value = None
                
                if rule.type == "css_link":
                    if re.search(pattern_to_match, css_links_text, re.IGNORECASE):
                        matched = True
                        match_value = css_links_text[:150]
                
                elif rule.type == "font_src_pattern":
                    if re.search(pattern_to_match, font_srcs_text, re.IGNORECASE):
                        matched = True
                        match_value = font_srcs_text[:150]
                
                elif rule.type == "image_src_pattern":
                    if re.search(pattern_to_match, image_srcs_text, re.IGNORECASE):
                        matched = True
                        match_value = image_srcs_text[:150]
                
                elif rule.type == "html_pattern":
                    if re.search(pattern_to_match, html, re.IGNORECASE):
                        matched = True
                        match_obj = re.search(pattern_to_match, html, re.IGNORECASE)
                        match_value = match_obj.group(0)[:150] if match_obj else "matched"
                
                elif rule.type == "script_src":
                    scripts_text = ' '.join(context.scripts)
                    if re.search(pattern_to_match, scripts_text, re.IGNORECASE):
                        matched = True
                        match_value = scripts_text[:150]
                
                # For header and dns_record types, these will be handled by other analyzers
                # but we include them here for completeness in the assets.yaml file
                elif rule.type == "header":
                    if rule.name and rule.name.lower() in context.headers:
                        header_value = context.headers[rule.name.lower()]
                        if re.search(pattern_to_match, header_value, re.IGNORECASE):
                            matched = True
                            match_value = header_value[:150]
                
                elif rule.type == "dns_record":
                    if rule.name and context.dns_records and rule.name in context.dns_records:
                        dns_values = ' '.join(str(v) for v in context.dns_records[rule.name])
                        if re.search(pattern_to_match, dns_values, re.IGNORECASE):
                            matched = True
                            match_value = dns_values[:150]
                
                if matched:
                    detections.append(
                        Detection(
                            name=tech.name,
                            category=tech.category,
                            confidence=rule.confidence,
                            evidence=Evidence(
                                type=rule.type,
                                pattern=pattern_to_match,
                                value=match_value or "matched",
                                name=rule.name
                            ),
                            version=tech.version
                        )
                    )
        
        return detections
