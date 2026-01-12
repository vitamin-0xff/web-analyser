"""API Key detection analyzers - finds exposed API keys in responses and error messages."""
from typing import List, Optional
import logging
import re
from core.context import ScanContext
from models.detection import Detection, Evidence
from models.technology import Technology
from core.analyzer_registry import AnalyzerRegistry, filter_by_rule_types
from fetch.http_client import fetch_url

logger = logging.getLogger(__name__)

# Common API key endpoints and paths that might expose keys
KEY_EXPOSURE_PATHS = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/config.php",
    "/config.json",
    "/settings.json",
    "/config/database.yml",
    "/config.yml",
    "/.git/config",
    "/package.json",
    "/requirements.txt",
    "/.aws/credentials",
    "/.ssh/id_rsa",
    "/private.key",
    "/server.key",
]


@AnalyzerRegistry.register(
    "api_keys_passive",
    lambda rules: filter_by_rule_types(rules, {"api_key_pattern", "private_key", "connection_string"}),
    analyzer_type="passive"
)
class APIKeyPassiveAnalyzer:
    """Passive analyzer that detects exposed API keys in the main page HTML only."""
    
    def __init__(self, rules: List[Technology]):
        self.rules = rules

    async def analyze(self, context: ScanContext) -> List[Detection]:
        """
        Scan for exposed API keys, secrets, and credentials in the fetched HTML.
        
        This is a PASSIVE analyzer - it only examines the main page content
        without making additional HTTP requests.
        """
        # Only scan the main page content
        return await self._scan_content(context.html, "main_page")

    async def _scan_content(self, content: str, source: str) -> List[Detection]:
        """Scan content for API keys using configured rules."""
        detections: List[Detection] = []
        
        for tech in self.rules:
            for rule in tech.evidence_rules:
                if rule.type == "api_key_pattern" and rule.pattern:
                    # Find all matches
                    matches = re.finditer(rule.pattern, content, re.IGNORECASE | re.MULTILINE)
                    
                    for match in matches:
                        # Extract the matched key (might want to mask it)
                        matched_key = match.group(0)
                        
                        # For security, only show last 8 chars
                        if len(matched_key) > 16:
                            display_key = "*" * (len(matched_key) - 8) + matched_key[-8:]
                        else:
                            display_key = "*" * len(matched_key)
                        
                        logger.warning(f"POTENTIAL EXPOSED KEY: {tech.name} found in {source}")
                        
                        detections.append(
                            Detection(
                                name=tech.name,
                                category=tech.category,
                                confidence=rule.confidence,
                                evidence=Evidence(
                                    type="api_key_pattern",
                                    value=display_key,  # Masked for security
                                    pattern=rule.pattern,
                                    name=f"Found in {source}"
                                ),
                                version=None
                            )
                        )
                
                elif rule.type == "private_key" and rule.pattern:
                    # Look for private keys (PEM format, etc.)
                    if re.search(rule.pattern, content, re.IGNORECASE | re.MULTILINE | re.DOTALL):
                        logger.warning(f"POTENTIAL PRIVATE KEY: {tech.name} found in {source}")
                        
                        detections.append(
                            Detection(
                                name=tech.name,
                                category=tech.category,
                                confidence=rule.confidence,
                                evidence=Evidence(
                                    type="private_key",
                                    value="[PRIVATE KEY DETECTED - MASKED]",
                                    pattern=rule.pattern,
                                    name=f"Found in {source}"
                                ),
                                version=None
                            )
                        )
                
                elif rule.type == "connection_string" and rule.pattern:
                    # Look for connection strings (databases, etc.)
                    if re.search(rule.pattern, content, re.IGNORECASE):
                        # Extract and mask the connection string
                        match = re.search(rule.pattern, content, re.IGNORECASE)
                        if match:
                            conn_str = match.group(0)
                            # Mask passwords and sensitive parts
                            masked = self._mask_connection_string(conn_str)
                            
                            logger.warning(f"POTENTIAL EXPOSED CONNECTION STRING: {tech.name} found in {source}")
                            
                            detections.append(
                                Detection(
                                    name=tech.name,
                                    category=tech.category,
                                    confidence=rule.confidence,
                                    evidence=Evidence(
                                        type="connection_string",
                                        value=masked,
                                        pattern=rule.pattern,
                                        name=f"Found in {source}"
                                    ),
                                    version=None
                                )
                            )
        
        return detections

    def _mask_connection_string(self, conn_str: str, reveal_length: int = 4) -> str:
        """Mask sensitive parts of a connection string while keeping structure visible."""
        # Mask passwords
        masked = re.sub(
            r'(password["\']?\s*[=:]?\s*)[^\s"\';,]+',
            r'\1' + '*' * 12,
            conn_str,
            flags=re.IGNORECASE
        )
        # Mask API keys in URLs
        masked = re.sub(
            r'([?&]api[_-]?key["\']?\s*[=:]?\s*)[^\s"\';,&]+',
            r'\1' + '*' * 12,
            masked,
            flags=re.IGNORECASE
        )
        return masked


@AnalyzerRegistry.register(
    "api_keys_active",
    lambda rules: filter_by_rule_types(rules, {"api_key_pattern", "private_key", "connection_string"}),
    analyzer_type="active"
)
class APIKeyActiveAnalyzer:
    """Active analyzer that detects exposed API keys by probing common credential exposure paths."""
    
    def __init__(self, rules: List[Technology]):
        self.rules = rules

    async def analyze(self, context: ScanContext) -> List[Detection]:
        """
        Scan for exposed API keys, secrets, and credentials via HTTP requests.
        
        This is an ACTIVE analyzer - it makes additional HTTP requests to common
        paths that might expose sensitive credentials (env files, config files, etc.).
        
        SECURITY WARNING: Use responsibly and only on authorized targets.
        """
        detections: List[Detection] = []
        base_url = context.url.rstrip('/')
        
        # Check the main page content first
        detections.extend(await self._scan_content(context.html, "main_page"))
        
        # Try common paths that might expose keys
        for path in KEY_EXPOSURE_PATHS:
            endpoint = f"{base_url}{path}"
            
            try:
                response = await fetch_url(endpoint, timeout=3)
                
                # Don't care about status code - even 404 might expose info
                logger.debug(f"Scanned {endpoint} (status: {response.status_code})")
                
                # Check response content for keys
                detections.extend(await self._scan_content(response.text, path))
            
            except Exception as e:
                logger.debug(f"API key scan failed for {endpoint}: {e}")
                continue
        
        return detections

    async def _scan_content(self, content: str, source: str) -> List[Detection]:
        """Scan content for API keys using configured rules."""
        detections: List[Detection] = []
        
        for tech in self.rules:
            for rule in tech.evidence_rules:
                if rule.type == "api_key_pattern" and rule.pattern:
                    # Find all matches
                    matches = re.finditer(rule.pattern, content, re.IGNORECASE | re.MULTILINE)
                    
                    for match in matches:
                        # Extract the matched key (might want to mask it)
                        matched_key = match.group(0)
                        
                        # For security, only show last 8 chars
                        if len(matched_key) > 16:
                            display_key = "*" * (len(matched_key) - 8) + matched_key[-8:]
                        else:
                            display_key = "*" * len(matched_key)
                        
                        logger.warning(f"POTENTIAL EXPOSED KEY: {tech.name} found in {source}")
                        
                        detections.append(
                            Detection(
                                name=tech.name,
                                category=tech.category,
                                confidence=rule.confidence,
                                evidence=Evidence(
                                    type="api_key_pattern",
                                    value=display_key,  # Masked for security
                                    pattern=rule.pattern,
                                    name=f"Found in {source}"
                                ),
                                version=None
                            )
                        )
                
                elif rule.type == "private_key" and rule.pattern:
                    # Look for private keys (PEM format, etc.)
                    if re.search(rule.pattern, content, re.IGNORECASE | re.MULTILINE | re.DOTALL):
                        logger.warning(f"POTENTIAL PRIVATE KEY: {tech.name} found in {source}")
                        
                        detections.append(
                            Detection(
                                name=tech.name,
                                category=tech.category,
                                confidence=rule.confidence,
                                evidence=Evidence(
                                    type="private_key",
                                    value="[PRIVATE KEY DETECTED - MASKED]",
                                    pattern=rule.pattern,
                                    name=f"Found in {source}"
                                ),
                                version=None
                            )
                        )
                
                elif rule.type == "connection_string" and rule.pattern:
                    # Look for connection strings (databases, etc.)
                    if re.search(rule.pattern, content, re.IGNORECASE):
                        # Extract and mask the connection string
                        match = re.search(rule.pattern, content, re.IGNORECASE)
                        if match:
                            conn_str = match.group(0)
                            # Mask passwords and sensitive parts
                            masked = self._mask_connection_string(conn_str)
                            
                            logger.warning(f"POTENTIAL EXPOSED CONNECTION STRING: {tech.name} found in {source}")
                            
                            detections.append(
                                Detection(
                                    name=tech.name,
                                    category=tech.category,
                                    confidence=rule.confidence,
                                    evidence=Evidence(
                                        type="connection_string",
                                        value=masked,
                                        pattern=rule.pattern,
                                        name=f"Found in {source}"
                                    ),
                                    version=None
                                )
                            )
        
        return detections

    def _mask_connection_string(self, conn_str: str, reveal_length: int = 4) -> str:
        """Mask sensitive parts of a connection string while keeping structure visible."""
        # Mask passwords
        masked = re.sub(
            r'(password["\']?\s*[=:]?\s*)[^\s"\';,]+',
            r'\1' + '*' * 12,
            conn_str,
            flags=re.IGNORECASE
        )
        # Mask API keys in URLs
        masked = re.sub(
            r'([?&]api[_-]?key["\']?\s*[=:]?\s*)[^\s"\';,&]+',
            r'\1' + '*' * 12,
            masked,
            flags=re.IGNORECASE
        )
        return masked
