from urllib.parse import urlparse, urljoin
import re
import hashlib
import logging
from core.context import ScanContext, TLSInfo
from core.cache import get_cache
from fetch.http_client import fetch_url
from fetch.dns_client import get_dns_records
from fetch.tls_client import get_tls_info
import asyncio
from typing import List, Any, Dict, Tuple, Optional, Set
from core.analyzer_registry import AnalyzerRegistry

# Import all analyzers to trigger @AnalyzerRegistry.register decorators
import analyzers.headers
import analyzers.html
import analyzers.js
import analyzers.cookies
import analyzers.network
import analyzers.css
import analyzers.meta_tags
import analyzers.structured_data
import analyzers.pwa
import analyzers.robots_sitemap
import analyzers.http_details
import analyzers.storage
import analyzers.endpoints
import analyzers.script_content
import analyzers.favicon
import analyzers.forms
import analyzers.sri
import analyzers.comments
import analyzers.assets
# Active detection analyzers (require --active flag)
import analyzers.graphql
import analyzers.api_probe
import analyzers.error_probe
import analyzers.api_keys

from models.detection import Detection, Evidence
from models.technology import Technology, EvidenceRule
from rules.rules_loader import load_rules

def _flatten_cert_info(cert_field_list: Tuple[Tuple[Tuple[str, str], ...], ...]) -> Dict[str, str]:
    """Helper to flatten the nested tuple structure of TLS cert issuer/subject."""
    result = {}
    for item_tuple in cert_field_list:
        if isinstance(item_tuple, tuple) and len(item_tuple) == 1 and \
           isinstance(item_tuple[0], tuple) and len(item_tuple[0]) == 2:
            key, value = item_tuple[0]
            result[key] = value
    return result

def _filter_technologies_by_rule_types(technologies: List[Technology], allowed: set[str]) -> List[Technology]:
    """Return Technology objects containing only evidence rules of allowed types.

    This avoids duplicating technologies per rule and reduces analyzer work.
    """
    filtered: List[Technology] = []
    for tech in technologies:
        subset = [r for r in tech.evidence_rules if r.type in allowed]
        if subset:
            filtered.append(
                Technology(
                    name=tech.name,
                    category=tech.category,
                    evidence_rules=subset,
                    version=tech.version,
                )
            )
    return filtered

class Engine:
    def __init__(self, exclude_analyzers: Set[str] = None):
        """Initialize the engine with dynamic analyzer registry.
        
        Args:
            exclude_analyzers: Set of analyzer names to exclude (e.g., {'html', 'js'})
        """
        self.logger = logging.getLogger(__name__)
        self.rules = load_rules()
        self.logger.info(f"Loaded {len(self.rules)} technology rules")
        
        # Instantiate all registered analyzers dynamically
        self.analyzers = AnalyzerRegistry.instantiate_all(self.rules, exclude=exclude_analyzers)
        self.logger.info(f"Initialized {len(self.analyzers)} analyzers")
        
        if exclude_analyzers:
            self.logger.info(f"Excluded analyzers: {', '.join(sorted(exclude_analyzers))}")

    async def scan_url(self, url: str) -> ScanContext:
        logger = logging.getLogger(__name__)
        logger.debug(f"Starting scan_url for {url}")
        loop = asyncio.get_running_loop()

        # 1. Fetch HTTP data (async)
        logger.debug(f"Fetching HTTP data from {url}")
        response = await fetch_url(url)
        logger.debug(f"HTTP response: status={response.status_code}, content-length={len(response.text)}")
        headers = {k.lower(): v for k, v in response.headers.items()}
        html_content = response.text
        cookies = dict(response.cookies)
        logger.debug(f"Found {len(cookies)} cookies")
        hostname = urlparse(url).hostname
        logger.debug(f"Hostname: {hostname}")

        # 2. Concurrently fetch DNS and TLS info (sync functions in executor)
        logger.debug("Fetching DNS records and TLS info concurrently")
        dns_task = loop.run_in_executor(
            None, get_dns_records, hostname, ["A", "CNAME", "MX", "TXT"]
        ) if hostname else asyncio.Future()

        tls_task = loop.run_in_executor(
            None, get_tls_info, url
        ) if url.startswith("https://") else asyncio.Future()

        if not hostname:
            dns_task.set_result({})
        if not url.startswith("https://"):
            tls_task.set_result(None)

        dns_records, raw_tls_info = await asyncio.gather(dns_task, tls_task)
        if dns_records:
            logger.debug(f"DNS records found: {list(dns_records.keys())}")
        if raw_tls_info:
            logger.debug(f"TLS certificate found for {url}")

        # 3. Process TLS info
        tls_info: Optional[TLSInfo] = None
        if raw_tls_info:
            tls_info = {
                "issuer": _flatten_cert_info(raw_tls_info.get("issuer", ())),
                "subject": _flatten_cert_info(raw_tls_info.get("subject", ())),
                "notBefore": raw_tls_info.get("notBefore"),
                "notAfter": raw_tls_info.get("notAfter"),
            }
            logger.debug(f"Processed TLS info: issuer={tls_info['issuer'].get('CN', 'N/A')}")

        # 4. Extract JS and script info from HTML
        logger.debug("Extracting scripts and stylesheets from HTML")
        scripts = [urljoin(url, src) for src in re.findall(r'<script\s+[^>]*src=["\']([^"\']+)["\']', html_content)]
        stylesheets = [urljoin(url, href) for href in re.findall(r'<link\s+[^>]*rel=["\']stylesheet["\'][^>]*href=["\']([^"\']+)["\']', html_content)]
        js_globals = set(re.findall(r'(?:window\.|var\s+|let\s+|const\s+)(\w+)\s*=', html_content))
        logger.debug(f"Found {len(scripts)} scripts, {len(stylesheets)} stylesheets, {len(js_globals)} JS globals")

        # 5. NEW: Extract PWA manifest and service worker
        manifest_match = re.search(r'<link\s+rel=["\']manifest["\'][^>]*href=["\']([^"\']+)["\']', html_content)
        manifest_url = urljoin(url, manifest_match.group(1)) if manifest_match else None
        if manifest_url:
            logger.debug(f"Found manifest: {manifest_url}")

        service_worker_match = re.search(r'navigator\.serviceWorker\.register\(["\']([^"\']+)["\']', html_content)
        service_worker_url = urljoin(url, service_worker_match.group(1)) if service_worker_match else None
        if service_worker_url:
            logger.debug(f"Found service worker: {service_worker_url}")

        # 6. NEW: Extract WASM modules
        wasm_modules = [urljoin(url, src) for src in re.findall(r'["\']([^"\']*\.wasm)["\']', html_content)]
        if wasm_modules:
            logger.debug(f"Found {len(wasm_modules)} WASM modules")

        # 7. NEW: Fetch robots.txt and sitemaps
        base_url = f"{urlparse(url).scheme}://{hostname}" if hostname else url
        logger.debug(f"Fetching robots.txt and sitemaps from {base_url}")
        robots_txt = await self._fetch_robots_txt(base_url)
        if robots_txt:
            logger.debug("robots.txt found")
        sitemaps = await self._fetch_sitemaps(base_url, robots_txt or "")
        if sitemaps:
            logger.debug(f"Found {len(sitemaps)} sitemaps")

        # 8. NEW: Fetch favicon and compute hash
        logger.debug("Fetching favicon")
        favicon_hash = await self._fetch_favicon_hash(base_url)
        if favicon_hash:
            logger.debug(f"Favicon hash: {favicon_hash}")

        context = ScanContext(
            url=url,
            headers=headers,
            html=html_content,
            cookies=cookies,
            scripts=scripts,
            stylesheets=stylesheets,
            js_globals=js_globals,
            tls=tls_info,
            dns_records=dns_records,
            manifest_url=manifest_url,
            service_worker_url=service_worker_url,
            status_code=response.status_code,
            http_version=getattr(response, 'http_version', None) or str(response.extensions.get('http_version')) if hasattr(response, 'extensions') else None,
            server_timing=headers.get('server-timing'),
            robots_txt=robots_txt,
            sitemaps=sitemaps or [],
            wasm_modules=wasm_modules or [],
            favicon_hash=favicon_hash
        )

        return context

    async def _fetch_robots_txt(self, base_url: str) -> Optional[str]:
        """Fetch /robots.txt from the domain with caching."""
        cache = get_cache()
        cache_key = f"robots_txt:{base_url}"
        
        # Check cache first
        cached = cache.get(cache_key)
        if cached is not None:
            return cached
        
        try:
            resp = await fetch_url(f"{base_url}/robots.txt")
            result = resp.text if resp.status_code == 200 else None
            # Cache for 10 minutes (robots.txt changes infrequently)
            cache.set(cache_key, result, ttl_seconds=600)
            return result
        except:
            cache.set(cache_key, None, ttl_seconds=600)
            return None

    async def _fetch_favicon_hash(self, base_url: str) -> Optional[str]:
        """Fetch favicon.ico and compute MD5 hash with caching."""
        cache = get_cache()
        cache_key = f"favicon_hash:{base_url}"
        
        # Check cache first
        cached = cache.get(cache_key)
        if cached is not None:
            return cached
        
        try:
            resp = await fetch_url(f"{base_url}/favicon.ico")
            if resp.status_code == 200:
                result = hashlib.md5(resp.content).hexdigest()
                # Cache for 1 hour (favicons change rarely)
                cache.set(cache_key, result, ttl_seconds=3600)
                return result
            cache.set(cache_key, None, ttl_seconds=3600)
            return None
        except:
            cache.set(cache_key, None, ttl_seconds=3600)
            return None

    async def _fetch_sitemaps(self, base_url: str, robots_txt: str) -> List[str]:
        """Extract sitemap URLs from robots.txt and check common paths."""
        sitemaps = []
        if robots_txt:
            sitemap_urls = re.findall(r'Sitemap:\s*(.+)', robots_txt)
            sitemaps.extend(sitemap_urls)
        
        # Check common sitemap locations
        for path in ['/sitemap.xml', '/sitemap_index.xml']:
            try:
                resp = await fetch_url(f"{base_url}{path}")
                if resp.status_code == 200:
                    sitemaps.append(f"{base_url}{path}")
            except:
                pass
        
        return sitemaps

    async def analyze_context(self, context: ScanContext) -> List[Detection]:
        logger = logging.getLogger(__name__)
        analyzer_timeout = 10  # seconds per analyzer to avoid hangs

        # Create tasks for all analyzers to run in parallel
        async def run_analyzer(name: str, analyzer) -> Tuple[str, List[Detection]]:
            logger.info(f"Running {name} analyzer")
            try:
                result = await asyncio.wait_for(analyzer.analyze(context), timeout=analyzer_timeout)
                if result:
                    logger.debug(f"{name} analyzer found {len(result)} technologies")
                else:
                    logger.debug(f"{name} analyzer found 0 technologies")
                return name, result or []
            except asyncio.TimeoutError:
                logger.warning(f"{name} analyzer timed out after {analyzer_timeout}s")
                return name, []
            except Exception as e:
                logger.error(f"Error in {name} analyzer: {e}", exc_info=True)
                return name, []

        # Run all analyzers in parallel
        tasks = [run_analyzer(name, analyzer) for name, analyzer in self.analyzers.items()]
        results = await asyncio.gather(*tasks)
        
        # Flatten all detections
        detections: List[Detection] = []
        for name, analyzer_detections in results:
            detections.extend(analyzer_detections)
        
        logger.debug(f"Aggregating {len(detections)} detections")
        return self._aggregate_detections(detections)

    def _aggregate_detections(self, detections: List[Detection]) -> List[Detection]:
        """Combine multiple hits per technology and sum confidences capped at 1.0."""
        by_name: Dict[str, Detection] = {}
        for d in detections:
            prev = by_name.get(d.name)
            if prev:
                total = min(1.0, prev.confidence + d.confidence)
                # Keep strongest evidence; merge version if one exists
                strongest = d if d.confidence > prev.confidence else prev
                by_name[d.name] = Detection(
                    name=prev.name,
                    category=prev.category,
                    confidence=total,
                    evidence=strongest.evidence,
                    version=prev.version or d.version,
                )
            else:
                by_name[d.name] = d
        return list(by_name.values())

# Example usage (for testing)
async def main():
    engine = Engine()
    context = await engine.scan_url("https://www.google.com")
    print(f"Scanned URL: {context.url}")
    print(f"Headers: {context.headers.keys()}")
    print(f"Cookies: {context.cookies.keys()}")
    print(f"TLS Info: {context.tls}")
    print(f"DNS Records: {context.dns_records}")
    print(f"HTML length: {len(context.html)}")
    print(f"Scripts: {context.scripts}")
    print(f"Stylesheets: {context.stylesheets}")

    detections = await engine.analyze_context(context)
    print("\n--- Detections ---")
    for detection in detections:
        print(f"  Name: {detection.name}, Category: {detection.category}, Confidence: {detection.confidence}, Evidence Type: {detection.evidence.type}")

if __name__ == "__main__":
    asyncio.run(main())
