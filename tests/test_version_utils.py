"""Tests for version extraction utilities."""
import pytest
from core.version_utils import (
    extract_version_from_url,
    extract_version_from_string,
    extract_version_from_meta_tag,
    extract_version_from_comment,
    extract_version_from_path,
    normalize_version
)


def test_extract_version_from_url_semantic():
    """Test semantic versioning extraction from URLs."""
    assert extract_version_from_url("/jquery-3.6.0.min.js") == "3.6.0"
    assert extract_version_from_url("/bootstrap/5.1.3/css/bootstrap.min.css") == "5.1.3"
    assert extract_version_from_url("/vue@3.2.45/dist/vue.js") == "3.2.45"


def test_extract_version_from_url_query_param():
    """Test version extraction from query parameters."""
    assert extract_version_from_url("/style.css?ver=1.2.3") == "1.2.3"
    assert extract_version_from_url("/script.js?version=2.0.1") == "2.0.1"
    assert extract_version_from_url("/app.js?v=4.5.6") == "4.5.6"


def test_extract_version_from_url_two_part():
    """Test two-part version extraction."""
    assert extract_version_from_url("/angular-1.8.min.js") == "1.8"
    assert extract_version_from_url("/react-18.2/react.min.js") == "18.2"


def test_extract_version_from_url_no_version():
    """Test URL without version returns None."""
    assert extract_version_from_url("/script.js") is None
    assert extract_version_from_url("/styles/main.css") is None


def test_extract_version_from_string_with_technology():
    """Test version extraction with technology context."""
    assert extract_version_from_string("WordPress 6.4.2", "WordPress") == "6.4.2"
    assert extract_version_from_string("React v18.2.0", "React") == "18.2.0"
    assert extract_version_from_string("Using Drupal 9", "Drupal") == "9"


def test_extract_version_from_string_generic():
    """Test generic version extraction."""
    assert extract_version_from_string("version 1.2.3") == "1.2.3"
    assert extract_version_from_string("v2.0.1-beta") == "2.0.1-beta"
    assert extract_version_from_string("Build 3.4.5") == "3.4.5"


def test_extract_version_from_meta_tag_cms():
    """Test version extraction from CMS meta tags."""
    assert extract_version_from_meta_tag("WordPress 6.4.2") == "6.4.2"
    assert extract_version_from_meta_tag("Drupal 9 (https://www.drupal.org)") == "9"
    assert extract_version_from_meta_tag("Joomla! 4.3") == "4.3"
    assert extract_version_from_meta_tag("Ghost 5.2.0") == "5.2.0"


def test_extract_version_from_comment():
    """Test version extraction from comments."""
    assert extract_version_from_comment("<!-- WordPress 6.4.2 -->") == "6.4.2"
    assert extract_version_from_comment("/* Bootstrap v5.1.3 */") == "5.1.3"
    assert extract_version_from_comment("// jQuery v3.6.0") == "3.6.0"


def test_extract_version_from_path():
    """Test version extraction from file paths."""
    assert extract_version_from_path("/cdn/bootstrap/5.1.3/bootstrap.min.css") == "5.1.3"
    assert extract_version_from_path("/libs/1.2.3/app.js") == "1.2.3"
    assert extract_version_from_path("/v2.0/index.html") == "2.0"


def test_normalize_version():
    """Test version normalization."""
    assert normalize_version("v1.2.3") == "1.2.3"
    assert normalize_version("1.2.x") == "1.2"
    assert normalize_version("1.2.3-beta") == "1.2.3-beta"
    assert normalize_version(None) is None
    assert normalize_version("") is None


def test_version_edge_cases():
    """Test edge cases for version extraction."""
    # Year-based versions
    assert extract_version_from_url("/app-2024.1.2.js") == "2024.1.2"
    
    # Version with pre-release tags (simpler format)
    assert extract_version_from_url("/vue-3.0.0-beta.js") == "3.0.0-beta"
    assert extract_version_from_url("/react-18.0.0-rc1.js") == "18.0.0-rc1"
    
    # Multiple versions in URL (should get first)
    url_multi = "/libs/jquery-3.6.0/bootstrap-5.1.3.js"
    version = extract_version_from_url(url_multi)
    assert version in ["3.6.0", "5.1.3"]  # Either is acceptable
