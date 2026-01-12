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
from typing import List, Any, Dict, Tuple, Optional

from analyzers.headers import HeadersAnalyzer
from analyzers.html import HtmlAnalyzer
from analyzers.js import JsAnalyzer
from analyzers.cookies import CookiesAnalyzer
from analyzers.network import NetworkAnalyzer
from analyzers.css import CssAnalyzer
from analyzers.meta_tags import MetaTagsAnalyzer
from analyzers.structured_data import StructuredDataAnalyzer
from analyzers.pwa import PWAAnalyzer
from analyzers.robots_sitemap import RobotsSitemapAnalyzer
from analyzers.http_details import HTTPDetailsAnalyzer
from analyzers.storage import StorageAnalyzer
from analyzers.endpoints import EndpointsAnalyzer
from analyzers.script_content import ScriptContentAnalyzer
from analyzers.favicon import FaviconAnalyzer
from analyzers.forms import FormsAnalyzer
from analyzers.sri import SRIAnalyzer
from analyzers.comments import CommentsAnalyzer
from analyzers.assets import AssetsAnalyzer
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
    def __init__(self):
        self.rules = load_rules()
        self.headers_analyzer = HeadersAnalyzer(
            _filter_technologies_by_rule_types(self.rules, {"header"})
        )
        self.html_analyzer = HtmlAnalyzer(
            _filter_technologies_by_rule_types(self.rules, {"html_pattern", "html_comment"})
        )
        self.js_analyzer = JsAnalyzer(
            _filter_technologies_by_rule_types(self.rules, {"script_src", "js_global"})
        )
        self.cookies_analyzer = CookiesAnalyzer(
            _filter_technologies_by_rule_types(self.rules, {"cookie"})
        )
        self.network_analyzer = NetworkAnalyzer(
            _filter_technologies_by_rule_types(self.rules, {"tls_issuer", "dns_record"})
        )
        self.css_analyzer = CssAnalyzer(
            _filter_technologies_by_rule_types(self.rules, {"css_link", "html_pattern"})
        )
        # NEW: Additional analyzers
        self.meta_tags_analyzer = MetaTagsAnalyzer(
            _filter_technologies_by_rule_types(self.rules, {"meta_name", "meta_property"})
        )
        self.structured_data_analyzer = StructuredDataAnalyzer(
            _filter_technologies_by_rule_types(self.rules, {"json_ld_pattern"})
        )
        self.pwa_analyzer = PWAAnalyzer(
            _filter_technologies_by_rule_types(self.rules, {"pwa_manifest", "service_worker"})
        )
        self.robots_sitemap_analyzer = RobotsSitemapAnalyzer(
            _filter_technologies_by_rule_types(self.rules, {"robots_txt", "sitemap_pattern"})
        )
        self.http_details_analyzer = HTTPDetailsAnalyzer(
            _filter_technologies_by_rule_types(self.rules, {"http_version", "server_timing"})
        )
        self.storage_analyzer = StorageAnalyzer(
            _filter_technologies_by_rule_types(self.rules, {"js_storage_key"})
        )
        self.endpoints_analyzer = EndpointsAnalyzer(
            _filter_technologies_by_rule_types(self.rules, {"graphql_endpoint", "openapi_url", "api_pattern"})
        )
        # PHASE 1: Passive analyzers
        self.script_content_analyzer = ScriptContentAnalyzer(
            _filter_technologies_by_rule_types(self.rules, {"script_content_pattern", "inline_js_variable"})
        )
        self.favicon_analyzer = FaviconAnalyzer(
            _filter_technologies_by_rule_types(self.rules, {"favicon_hash"})
        )
        self.forms_analyzer = FormsAnalyzer(
            _filter_technologies_by_rule_types(self.rules, {"form_action_pattern", "hidden_field_name"})
        )
        self.sri_analyzer = SRIAnalyzer(
            _filter_technologies_by_rule_types(self.rules, {"sri_hash"})
        )
        self.comments_analyzer = CommentsAnalyzer(
            _filter_technologies_by_rule_types(self.rules, {"html_comment", "css_comment", "js_comment"})
        )
        # Assets analyzer
        self.assets_analyzer = AssetsAnalyzer(
            _filter_technologies_by_rule_types(self.rules, {
                "css_link", "font_src_pattern", "image_src_pattern", 
                "html_pattern", "script_src", "header", "dns_record"
            })
        )

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
        detections: List[Detection] = []
        
        analyzers = [
            ("headers", self.headers_analyzer),
            ("html", self.html_analyzer),
            ("js", self.js_analyzer),
            ("cookies", self.cookies_analyzer),
            ("network", self.network_analyzer),
            ("css", self.css_analyzer),
            ("meta_tags", self.meta_tags_analyzer),
            ("structured_data", self.structured_data_analyzer),
            ("pwa", self.pwa_analyzer),
            ("robots_sitemap", self.robots_sitemap_analyzer),
            ("http_details", self.http_details_analyzer),
            ("storage", self.storage_analyzer),
            ("endpoints", self.endpoints_analyzer),
            ("script_content", self.script_content_analyzer),
            ("favicon", self.favicon_analyzer),
            ("forms", self.forms_analyzer),
            ("sri", self.sri_analyzer),
            ("comments", self.comments_analyzer),
            ("assets", self.assets_analyzer),
        ]
        
        for name, analyzer in analyzers:
            logger.debug(f"Running {name} analyzer")
            result = await analyzer.analyze(context)
            if result:
                logger.debug(f"{name} analyzer found {len(result)} technologies")
                detections.extend(result)
            else:
                logger.debug(f"{name} analyzer found 0 technologies")
        
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
