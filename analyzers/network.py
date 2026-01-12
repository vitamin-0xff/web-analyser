from typing import List
import re
from core.context import ScanContext
from models.detection import Detection, Evidence
from models.technology import Technology

class NetworkAnalyzer:
    def __init__(self, rules: List[Technology]):
        self.rules = rules

    async def analyze(self, context: ScanContext) -> List[Detection]:
        detections: List[Detection] = []

        for tech in self.rules:
            for rule in tech.evidence_rules:
                if rule.type not in ["tls_issuer", "dns_record"]:
                    continue

                if rule.type == "tls_issuer" and context.tls and rule.name:
                    # Check for rule.name (e.g., "commonName") within TLS issuer info
                    issuer_info = context.tls.get("issuer", {})
                    field_value = issuer_info.get(rule.name, "")
                    
                    if field_value and rule.pattern and re.search(rule.pattern, field_value, re.IGNORECASE):
                        detections.append(
                            Detection(
                                name=tech.name,
                                category=tech.category,
                                confidence=rule.confidence,
                                evidence=Evidence(
                                    type="tls_issuer",
                                    name=rule.name,
                                    value=field_value,
                                    pattern=rule.pattern
                                ),
                                version=tech.version
                            )
                        )
                
                elif rule.type == "dns_record" and rule.name and context.dns_records:
                    # Check for rule.name (e.g., "A", "CNAME", "TXT") within DNS records
                    records_for_type = context.dns_records.get(rule.name, [])
                    for record_value in records_for_type:
                        if rule.pattern and re.search(rule.pattern, record_value, re.IGNORECASE):
                            detections.append(
                                Detection(
                                    name=tech.name,
                                    category=tech.category,
                                    confidence=rule.confidence,
                                    evidence=Evidence(
                                        type="dns_record",
                                        name=rule.name,
                                        value=record_value,
                                        pattern=rule.pattern
                                    ),
                                    version=tech.version
                                )
                            )
        return detections
