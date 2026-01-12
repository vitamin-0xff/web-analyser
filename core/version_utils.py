"""
Utility functions for extracting technology versions from various sources.
"""
import re
from typing import Optional


# Common version patterns (order matters - most specific first)
VERSION_PATTERNS = [
    # Year-based versions (2024.1.2, 2024.1)
    r'v?(\d{4}\.\d+\.\d+)',
    r'v?(\d{4}\.\d+)',
    # Semantic versioning with pre-release (1.2.3-beta2, 1.2.3-rc1) - no file extension
    r'v?(\d+\.\d+\.\d+-[a-z]+\d*)(?=\D|$)',
    # Semantic versioning (1.2.3, v1.2.3)
    r'v?(\d+\.\d+\.\d+)',
    # Two-part versions (1.2, 1.2.x)
    r'v?(\d+\.\d+(?:\.x)?)',
    # Single version with suffix (5.x, 8.x)
    r'v?(\d+\.x)',
]


def extract_version_from_url(url: str) -> Optional[str]:
    """
    Extract version from a URL path or filename.
    
    Examples:
        - /jquery-3.6.0.min.js -> 3.6.0
        - /bootstrap/5.1.3/css/bootstrap.min.css -> 5.1.3
        - /wp-content/themes/twentytwenty-one/style.css?ver=1.4 -> 1.4
    
    Args:
        url: The URL or path to extract version from
    
    Returns:
        Extracted version string or None
    """
    # Try query parameters first (e.g., ?ver=1.2.3)
    query_match = re.search(r'[?&](?:ver|version|v)=([0-9.a-z-]+)', url, re.IGNORECASE)
    if query_match:
        return query_match.group(1)
    
    # Try to find version in the path
    for pattern in VERSION_PATTERNS:
        match = re.search(pattern, url)
        if match:
            return match.group(1)
    
    return None


def extract_version_from_string(text: str, technology: str = None) -> Optional[str]:
    """
    Extract version from a generic string (meta tag, comment, etc.).
    
    Examples:
        - "WordPress 6.4.2" -> 6.4.2
        - "generator: Drupal 9 (https://www.drupal.org)" -> 9
        - "React v18.2.0" -> 18.2.0
    
    Args:
        text: The text to search for version
        technology: Optional technology name to look for context
    
    Returns:
        Extracted version string or None
    """
    if not text:
        return None
    
    # If technology name is provided, look for it followed by version
    if technology:
        # Try "TechnologyName 1.2.3" or "TechnologyName v1.2.3"
        tech_pattern = rf'{re.escape(technology)}\s+v?(\d+(?:\.\d+)*(?:\.\d+)?(?:-[a-z0-9.]+)?)'
        match = re.search(tech_pattern, text, re.IGNORECASE)
        if match:
            return match.group(1)
    
    # Try common version patterns
    for pattern in VERSION_PATTERNS:
        match = re.search(pattern, text)
        if match:
            return match.group(1)
    
    return None


def extract_version_from_meta_tag(meta_content: str, meta_name: str = None) -> Optional[str]:
    """
    Extract version from meta tag content.
    
    Examples:
        - meta generator="WordPress 6.4.2" -> 6.4.2
        - meta name="generator" content="Drupal 9 (https://www.drupal.org)" -> 9
    
    Args:
        meta_content: The content attribute value
        meta_name: The name attribute value (for context)
    
    Returns:
        Extracted version string or None
    """
    if not meta_content:
        return None
    
    # Common CMS patterns
    cms_patterns = [
        (r'WordPress\s+(\d+\.\d+(?:\.\d+)?)', None),
        (r'Drupal\s+(\d+)', None),
        (r'Joomla!\s+(\d+\.\d+)', None),
        (r'Ghost\s+(\d+\.\d+\.\d+)', None),
    ]
    
    for pattern, _ in cms_patterns:
        match = re.search(pattern, meta_content, re.IGNORECASE)
        if match:
            return match.group(1)
    
    # Fallback to generic extraction
    return extract_version_from_string(meta_content)


def extract_version_from_comment(comment: str) -> Optional[str]:
    """
    Extract version from HTML/JS/CSS comments.
    
    Examples:
        - "<!-- WordPress 6.4.2 -->" -> 6.4.2
        - "/* Bootstrap v5.1.3 */" -> 5.1.3
        - "// jQuery v3.6.0" -> 3.6.0
    
    Args:
        comment: The comment text
    
    Returns:
        Extracted version string or None
    """
    return extract_version_from_string(comment)


def extract_version_from_path(path: str, technology: str = None) -> Optional[str]:
    """
    Extract version from file paths like /cdn/bootstrap/5.1.3/bootstrap.min.css
    
    Args:
        path: The file path
        technology: Optional technology name for context
    
    Returns:
        Extracted version string or None
    """
    # Look for version-like segments in path
    segments = path.split('/')
    for segment in segments:
        for pattern in VERSION_PATTERNS:
            match = re.match(f'^{pattern}$', segment)
            if match:
                return match.group(1)
    
    return None


def normalize_version(version: Optional[str]) -> Optional[str]:
    """
    Normalize version string for consistency.
    
    Examples:
        - "v1.2.3" -> "1.2.3"
        - "1.2.x" -> "1.2"
        - "1.2.3-beta" -> "1.2.3-beta"
    
    Args:
        version: Version string to normalize
    
    Returns:
        Normalized version or None
    """
    if not version:
        return None
    
    # Remove leading 'v'
    version = version.lstrip('v')
    
    # Remove trailing '.x'
    version = re.sub(r'\.x$', '', version)
    
    return version if version else None
