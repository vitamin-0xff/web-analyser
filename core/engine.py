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

        context = ScanContext(
            url=url,
            headers=headers,
            html=html_content,
            cookies=cookies,
            scripts=scripts,
            stylesheets=stylesheets,
            js_globals=js_globals,
            tls=tls_info,
            dns_records=dns_records
        )

        return context

    async def analyze_context(self, context: ScanContext) -> List[Detection]:
        detections: List[Detection] = []
        detections.extend(await self.headers_analyzer.analyze(context))
        detections.extend(await self.html_analyzer.analyze(context))
        detections.extend(await self.js_analyzer.analyze(context))
        detections.extend(await self.cookies_analyzer.analyze(context))
        detections.extend(await self.network_analyzer.analyze(context))
        detections.extend(await self.css_analyzer.analyze(context))
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
