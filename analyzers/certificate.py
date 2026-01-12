"""Certificate-based detection analyzer for identifying hosted services and infrastructure."""
from typing import List, Optional, Dict
import logging
import re
from core.context import ScanContext
from models.detection import Detection, Evidence
from models.technology import Technology
from core.analyzer_registry import AnalyzerRegistry, filter_by_rule_types

logger = logging.getLogger(__name__)


@AnalyzerRegistry.register(
    "certificate",
    lambda rules: filter_by_rule_types(rules, {"certificate_issuer", "certificate_cn", "certificate_san"}),
    analyzer_type="passive"
)
class CertificateAnalyzer:
    """Passive analyzer that detects technologies from SSL/TLS certificate information."""
    
    def __init__(self, rules: List[Technology]):
        self.rules = rules

    async def analyze(self, context: ScanContext) -> List[Detection]:
        """
        Analyze SSL/TLS certificate for technology fingerprints.
        
        This is a PASSIVE analyzer - it only examines existing certificate data.
        """
        detections: List[Detection] = []
        
        # Check if TLS information is available
        if not context.tls:
            return detections
        
        tls_data = context.tls
        
        # Extract certificate data (handle dict values)
        issuer_raw = tls_data.get('issuer', '')
        issuer = str(issuer_raw).lower() if issuer_raw else ''
        
        cn_raw = tls_data.get('cn', '')
        cn = str(cn_raw).lower() if cn_raw else ''
        
        san = tls_data.get('san', [])
        san_lower = [s.lower() for s in san] if san else []
        
        # Convert to searchable strings
        issuer_text = issuer
        cn_text = cn
        san_text = ' '.join(san_lower)
        certificate_text = f"{issuer_text} {cn_text} {san_text}"
        
        logger.debug(f"Analyzing certificate: issuer={issuer}, cn={cn}, san_count={len(san_lower)}")
        
        # Match against rules
        for tech in self.rules:
            for rule in tech.evidence_rules:
                if rule.type == "certificate_issuer" and rule.pattern:
                    # Match certificate issuer
                    if self._match_pattern(rule.pattern, issuer_text):
                        detections.append(
                            Detection(
                                name=tech.name,
                                category=tech.category,
                                confidence=rule.confidence,
                                evidence=Evidence(
                                    type="certificate_issuer",
                                    value=issuer,
                                    pattern=rule.pattern
                                ),
                                version=tech.version
                            )
                        )
                
                elif rule.type == "certificate_cn" and rule.pattern:
                    # Match common name (domain)
                    if self._match_pattern(rule.pattern, cn_text):
                        detections.append(
                            Detection(
                                name=tech.name,
                                category=tech.category,
                                confidence=rule.confidence,
                                evidence=Evidence(
                                    type="certificate_cn",
                                    value=cn,
                                    pattern=rule.pattern
                                ),
                                version=tech.version
                            )
                        )
                
                elif rule.type == "certificate_san" and rule.pattern:
                    # Match Subject Alternative Names (wildcard domains, subdomains)
                    if self._match_pattern(rule.pattern, san_text):
                        # Find which SAN matched
                        for san_entry in san_lower:
                            if self._match_pattern(rule.pattern, san_entry):
                                detections.append(
                                    Detection(
                                        name=tech.name,
                                        category=tech.category,
                                        confidence=rule.confidence,
                                        evidence=Evidence(
                                            type="certificate_san",
                                            value=san_entry,
                                            pattern=rule.pattern
                                        ),
                                        version=tech.version
                                    )
                                )
                                break  # Only report first match
        
        return detections

    def _match_pattern(self, pattern: str, text: str) -> bool:
        """Check if pattern matches text (case-insensitive)."""
        try:
            return bool(re.search(pattern, text, re.IGNORECASE))
        except Exception:
            return pattern.lower() in text.lower()
