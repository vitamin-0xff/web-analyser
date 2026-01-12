from dataclasses import dataclass, field
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
    
    # NEW: PWA & Manifest
    manifest_url: Optional[str] = None
    service_worker_url: Optional[str] = None
    
    # NEW: HTTP metadata
    status_code: Optional[int] = None
    http_version: Optional[str] = None
    server_timing: Optional[str] = None
    
    # NEW: Robots & Sitemap
    robots_txt: Optional[str] = None
    sitemaps: Optional[List[str]] = field(default_factory=list)
    
    # NEW: WebAssembly
    wasm_modules: Optional[List[str]] = field(default_factory=list)
