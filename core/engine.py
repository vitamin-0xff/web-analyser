from urllib.parse import urlparse, urljoin
import re
from core.context import ScanContext, TLSInfo
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

    async def scan_url(self, url: str) -> ScanContext:
        loop = asyncio.get_running_loop()

        # 1. Fetch HTTP data (async)
        response = await fetch_url(url)
        headers = {k.lower(): v for k, v in response.headers.items()}
        html_content = response.text
        cookies = dict(response.cookies)
        hostname = urlparse(url).hostname

        # 2. Concurrently fetch DNS and TLS info (sync functions in executor)
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

        # 3. Process TLS info
        tls_info: Optional[TLSInfo] = None
        if raw_tls_info:
            tls_info = {
                "issuer": _flatten_cert_info(raw_tls_info.get("issuer", ())),
                "subject": _flatten_cert_info(raw_tls_info.get("subject", ())),
                "notBefore": raw_tls_info.get("notBefore"),
                "notAfter": raw_tls_info.get("notAfter"),
            }

        # 4. Extract JS and script info from HTML
        scripts = [urljoin(url, src) for src in re.findall(r'<script\s+[^>]*src=["\']([^"\']+)["\']', html_content)]
        stylesheets = [urljoin(url, href) for href in re.findall(r'<link\s+[^>]*rel=["\']stylesheet["\'][^>]*href=["\']([^"\']+)["\']', html_content)]
        js_globals = set(re.findall(r'(?:window\.|var\s+|let\s+|const\s+)(\w+)\s*=', html_content))

        # 5. NEW: Extract PWA manifest and service worker
        manifest_match = re.search(r'<link\s+rel=["\']manifest["\'][^>]*href=["\']([^"\']+)["\']', html_content)
        manifest_url = urljoin(url, manifest_match.group(1)) if manifest_match else None

        service_worker_match = re.search(r'navigator\.serviceWorker\.register\(["\']([^"\']+)["\']', html_content)
        service_worker_url = urljoin(url, service_worker_match.group(1)) if service_worker_match else None

        # 6. NEW: Extract WASM modules
        wasm_modules = [urljoin(url, src) for src in re.findall(r'["\']([^"\']*\.wasm)["\']', html_content)]

        # 7. NEW: Fetch robots.txt and sitemaps
        base_url = f"{urlparse(url).scheme}://{hostname}" if hostname else url
        robots_txt = await self._fetch_robots_txt(base_url)
        sitemaps = await self._fetch_sitemaps(base_url, robots_txt or "")

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
            wasm_modules=wasm_modules or []
        )

        return context

    async def _fetch_robots_txt(self, base_url: str) -> Optional[str]:
        """Fetch /robots.txt from the domain."""
        try:
            resp = await fetch_url(f"{base_url}/robots.txt")
            return resp.text if resp.status_code == 200 else None
        except:
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
        detections: List[Detection] = []
        detections.extend(await self.headers_analyzer.analyze(context))
        detections.extend(await self.html_analyzer.analyze(context))
        detections.extend(await self.js_analyzer.analyze(context))
        detections.extend(await self.cookies_analyzer.analyze(context))
        detections.extend(await self.network_analyzer.analyze(context))
        detections.extend(await self.css_analyzer.analyze(context))
        # NEW: Additional analyzers
        detections.extend(await self.meta_tags_analyzer.analyze(context))
        detections.extend(await self.structured_data_analyzer.analyze(context))
        detections.extend(await self.pwa_analyzer.analyze(context))
        detections.extend(await self.robots_sitemap_analyzer.analyze(context))
        detections.extend(await self.http_details_analyzer.analyze(context))
        detections.extend(await self.storage_analyzer.analyze(context))
        detections.extend(await self.endpoints_analyzer.analyze(context))
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
