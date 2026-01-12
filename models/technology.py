from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

@dataclass(frozen=True)
class EvidenceRule:
    """Defines a rule for detecting a technology."""
    type: str # e.g., 'js_global', 'header', 'html_pattern'
    name: Optional[str] = None # Name of the item to check (e.g., header name, meta tag name)
    value: Optional[str] = None # The value of the item to check (for exact matches)
    pattern: Optional[str] = None # Regex pattern to match against the item's value
    confidence: float = 0.5 # Confidence score for this piece of evidence

@dataclass(frozen=True)
class Technology:
    """Represents a technology and its detection rules."""
    name: str
    category: str
    evidence_rules: List[EvidenceRule] = field(default_factory=list)
    version: Optional[str] = None # A way to infer version if available in rules
    # Add fields for exclusivity, implies, requires, etc. if needed later
