from typing import List
import re
import time
import asyncio
import logging

try:
    import regex as regex_lib
except ImportError:  # regex is optional; fallback to stdlib re without timeouts
    regex_lib = None

# Warn on slow regex evaluation to surface problematic patterns
PATTERN_SLOW_THRESHOLD_SECONDS = 0.5
# Hard timeout to prevent catastrophic regex backtracking (ms for regex lib, seconds for fallback)
REGEX_TIMEOUT_MS = 800
PATTERN_TIMEOUT_SECONDS = 1.0
# Cap HTML scanned by regex to avoid catastrophic backtracking on huge pages
MAX_HTML_SCAN_LENGTH = 200_000
from core.context import ScanContext
from models.detection import Detection, Evidence
from models.technology import Technology

class HtmlAnalyzer:
    def __init__(self, rules: List[Technology]):
        self.rules = rules

    async def analyze(self, context: ScanContext) -> List[Detection]:
        logger = logging.getLogger(__name__)
        detections: List[Detection] = []
        html_content = context.html
        scan_html = html_content
        if len(html_content) > MAX_HTML_SCAN_LENGTH:
            scan_html = html_content[:MAX_HTML_SCAN_LENGTH]
            logger.debug(f"HtmlAnalyzer truncating HTML for scanning to {MAX_HTML_SCAN_LENGTH} chars (original {len(html_content)})")
        match_count = 0

        for tech in self.rules:
            for rule in tech.evidence_rules:
                if rule.type not in ["html_pattern", "html_comment"]:
                    continue

                if rule.pattern:
                    match, duration = await self._search_with_timeout(rule.pattern, scan_html, logger)

                    if duration > PATTERN_SLOW_THRESHOLD_SECONDS:
                        logger.warning(f"HtmlAnalyzer slow pattern for {tech.name} ({rule.type}) took {duration:.2f}s")

                    if match:
                        logger.debug(f"HtmlAnalyzer matched {tech.name} on {rule.type}")
                        match_count += 1
                        detections.append(
                            Detection(
                                name=tech.name,
                                category=tech.category,
                                confidence=rule.confidence,
                                evidence=Evidence(
                                    type=rule.type,
                                    pattern=rule.pattern,
                                    value=match.group(0) # The matched string
                                ),
                                version=self._extract_version(match.group(0)) # Try to extract version from match
                            )
                        )
                # For exact value match in HTML (less common for HTML patterns)
                elif rule.value and rule.value.lower() in scan_html.lower():
                    logger.debug(f"HtmlAnalyzer matched {tech.name} on value {rule.value}")
                    match_count += 1
                    detections.append(
                        Detection(
                            name=tech.name,
                            category=tech.category,
                            confidence=rule.confidence,
                            evidence=Evidence(
                                type=rule.type,
                                value=rule.value
                            ),
                            version=tech.version
                        )
                    )

        logger.debug(f"HtmlAnalyzer: {match_count} matches, {len(detections)} detections")
        return detections

    def _extract_version(self, text: str) -> str | None:
        """Extracts a version number from a string."""
        match = re.search(r'(\d+\.\d+(\.\d+)?)', text)
        return match.group(1) if match else None

    async def _search_with_timeout(self, pattern: str, text: str, logger: logging.Logger):
        """Run regex search in a thread with a timeout to avoid blocking the event loop."""
        start = time.perf_counter()
        if regex_lib:
            try:
                match = regex_lib.search(pattern, text, regex_lib.IGNORECASE, timeout=REGEX_TIMEOUT_MS)
                duration = time.perf_counter() - start
                return match, duration
            except regex_lib.TimeoutError:
                duration = time.perf_counter() - start
                logger.warning(f"HtmlAnalyzer pattern timeout for pattern {pattern[:50]}... ({duration:.2f}s)")
                return None, duration

        # Fallback: run in a thread with asyncio timeout (thread may keep running, but we return early)
        try:
            match = await asyncio.wait_for(
                asyncio.to_thread(re.search, pattern, text, re.IGNORECASE),
                timeout=PATTERN_TIMEOUT_SECONDS
            )
            duration = time.perf_counter() - start
            return match, duration
        except asyncio.TimeoutError:
            duration = time.perf_counter() - start
            logger.warning(f"HtmlAnalyzer pattern timeout for pattern {pattern[:50]}... ({duration:.2f}s)")
            return None, duration
