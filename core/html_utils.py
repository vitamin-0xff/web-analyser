"""Utilities for processing HTML content in parallel chunks."""
import re
import asyncio
import logging
from typing import List, Tuple, Optional, Set
from dataclasses import dataclass

try:
    import regex as regex_lib
except ImportError:
    regex_lib = None

# Configuration
CHUNK_SIZE = 50_000  # 50KB chunks
CHUNK_OVERLAP = 2_000  # 2KB overlap to catch patterns at boundaries
MAX_HTML_SIZE = 1_000_000  # 1MB - skip HTML pattern matching above this
PATTERN_TIMEOUT = 0.3  # 300ms timeout per pattern per chunk

logger = logging.getLogger(__name__)


@dataclass
class HtmlMatch:
    """Represents a regex match in HTML with position info for deduplication."""
    matched_text: str
    start_pos: int
    end_pos: int
    chunk_id: int


async def search_html_parallel(
    pattern: str,
    html: str,
    flags: int = re.IGNORECASE,
    tech_name: str = "Unknown"
) -> Optional[re.Match]:
    """
    Search for a pattern in HTML using parallel chunk processing.
    
    Args:
        pattern: Regex pattern to search for
        html: HTML content to search in
        flags: Regex flags (default: re.IGNORECASE)
        tech_name: Technology name for logging
    
    Returns:
        First match found, or None if no match or timeout
    """
    # Skip on very large HTML
    if len(html) > MAX_HTML_SIZE:
        logger.debug(f"Skipping pattern for {tech_name} - HTML too large ({len(html)} bytes)")
        return None
    
    # For small HTML, just search directly
    if len(html) <= CHUNK_SIZE:
        return await _search_with_timeout(pattern, html, flags)
    
    # Split into overlapping chunks
    chunks = _create_chunks(html)
    
    # Search all chunks in parallel
    tasks = [
        _search_chunk(pattern, chunk, offset, chunk_id, flags)
        for chunk_id, (chunk, offset) in enumerate(chunks)
    ]
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Return first successful match
    for result in results:
        if isinstance(result, re.Match):
            return result
        elif isinstance(result, Exception):
            logger.debug(f"Chunk search error for {tech_name}: {result}")
    
    return None


async def findall_html_parallel(
    pattern: str,
    html: str,
    flags: int = re.IGNORECASE,
    tech_name: str = "Unknown"
) -> List[str]:
    """
    Find all matches of a pattern in HTML using parallel chunk processing.
    Automatically deduplicates matches found in overlapping regions.
    
    Args:
        pattern: Regex pattern to search for
        html: HTML content to search in
        flags: Regex flags (default: re.IGNORECASE)
        tech_name: Technology name for logging
    
    Returns:
        List of unique matched strings
    """
    # Skip on very large HTML
    if len(html) > MAX_HTML_SIZE:
        logger.debug(f"Skipping pattern for {tech_name} - HTML too large ({len(html)} bytes)")
        return []
    
    # For small HTML, just search directly
    if len(html) <= CHUNK_SIZE:
        try:
            matches = await asyncio.wait_for(
                asyncio.to_thread(re.findall, pattern, html, flags),
                timeout=PATTERN_TIMEOUT * 2
            )
            return matches
        except asyncio.TimeoutError:
            logger.warning(f"Pattern timeout for {tech_name}")
            return []
    
    # Split into overlapping chunks
    chunks = _create_chunks(html)
    
    # Search all chunks in parallel
    tasks = [
        _findall_chunk(pattern, chunk, offset, chunk_id, flags)
        for chunk_id, (chunk, offset) in enumerate(chunks)
    ]
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Deduplicate matches from overlapping regions
    all_matches: List[HtmlMatch] = []
    for result in results:
        if isinstance(result, list):
            all_matches.extend(result)
        elif isinstance(result, Exception):
            logger.debug(f"Chunk findall error for {tech_name}: {result}")
    
    # Deduplicate by position - keep unique matches
    return _deduplicate_matches(all_matches)


def _create_chunks(html: str) -> List[Tuple[str, int]]:
    """
    Split HTML into overlapping chunks.
    
    Returns:
        List of (chunk_text, start_offset) tuples
    """
    chunks = []
    pos = 0
    
    while pos < len(html):
        # Start of this chunk (with overlap from previous)
        chunk_start = max(0, pos - CHUNK_OVERLAP)
        chunk_end = min(len(html), pos + CHUNK_SIZE)
        
        chunk = html[chunk_start:chunk_end]
        chunks.append((chunk, chunk_start))
        
        # Move to next chunk
        pos += CHUNK_SIZE
        
        # Break if we've reached the end
        if chunk_end >= len(html):
            break
    
    return chunks


async def _search_chunk(
    pattern: str,
    chunk: str,
    offset: int,
    chunk_id: int,
    flags: int
) -> Optional[re.Match]:
    """Search for pattern in a single chunk with timeout."""
    match = await _search_with_timeout(pattern, chunk, flags)
    return match


async def _findall_chunk(
    pattern: str,
    chunk: str,
    offset: int,
    chunk_id: int,
    flags: int
) -> List[HtmlMatch]:
    """Find all matches in a single chunk with timeout."""
    try:
        # Use regex library with timeout if available
        if regex_lib:
            matches = regex_lib.findall(pattern, chunk, flags, timeout=PATTERN_TIMEOUT)
        else:
            matches = await asyncio.wait_for(
                asyncio.to_thread(re.findall, pattern, chunk, flags),
                timeout=PATTERN_TIMEOUT
            )
        
        # Find positions for each match for deduplication
        html_matches = []
        for match_text in matches:
            # Find this match's position in the chunk
            pos = chunk.find(match_text)
            if pos >= 0:
                html_matches.append(HtmlMatch(
                    matched_text=match_text,
                    start_pos=offset + pos,
                    end_pos=offset + pos + len(match_text),
                    chunk_id=chunk_id
                ))
        
        return html_matches
    except (asyncio.TimeoutError, TimeoutError):
        logger.debug(f"Chunk {chunk_id} search timeout")
        return []
    except Exception as e:
        logger.debug(f"Chunk {chunk_id} search error: {e}")
        return []


async def _search_with_timeout(
    pattern: str,
    text: str,
    flags: int
) -> Optional[re.Match]:
    """Search with timeout protection."""
    try:
        if regex_lib:
            match = regex_lib.search(pattern, text, flags, timeout=PATTERN_TIMEOUT)
        else:
            match = await asyncio.wait_for(
                asyncio.to_thread(re.search, pattern, text, flags),
                timeout=PATTERN_TIMEOUT
            )
        return match
    except (asyncio.TimeoutError, TimeoutError):
        return None
    except Exception:
        return None


def _deduplicate_matches(matches: List[HtmlMatch]) -> List[str]:
    """
    Deduplicate matches that appear in multiple chunks due to overlap.
    Keep matches based on their position in the original HTML.
    """
    if not matches:
        return []
    
    # Sort by position
    matches.sort(key=lambda m: m.start_pos)
    
    # Remove duplicates - if same position, keep one
    seen_positions: Set[Tuple[int, int]] = set()
    unique_matches = []
    
    for match in matches:
        pos_key = (match.start_pos, match.end_pos)
        if pos_key not in seen_positions:
            seen_positions.add(pos_key)
            unique_matches.append(match.matched_text)
    
    return unique_matches
