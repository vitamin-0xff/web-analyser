from dataclasses import dataclass, field
from typing import Dict, Any, Optional

@dataclass(frozen=True)
class Evidence:
    """Represents a piece of evidence for a technology detection."""
    type: str
    name: Optional[str] = None
    pattern: Optional[str] = None
    value: Optional[str] = None
    # Add other fields as needed for specific evidence types
    # For example, for 'js_global', 'value' could be the global variable name.

@dataclass(frozen=True)
class Detection:
    """Represents a detected technology."""
    name: str
    category: str
    confidence: float
    evidence: Evidence
    version: Optional[str] = None # Will be inferred if available
