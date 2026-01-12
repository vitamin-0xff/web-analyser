from dataclasses import dataclass
from typing import Dict, List, Set, Optional, Any

# Placeholder for TLSInfo. This could be a more structured dataclass later.
TLSInfo = Dict[str, Any]

@dataclass(frozen=True)
class ScanContext:
    url: str
    headers: Dict[str, str]
    html: str
    cookies: Dict[str, str]
    scripts: List[str] # URLs of scripts
    stylesheets: List[str] # URLs of stylesheets
    js_globals: Set[str] # Global JavaScript variables/objects
    tls: Optional[TLSInfo]
    dns_records: Dict[str, List[str]] # e.g., {"A": ["1.2.3.4"], "CNAME": ["example.com"]}
