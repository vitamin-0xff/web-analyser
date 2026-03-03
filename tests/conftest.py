"""Shared pytest fixtures for web-analyser tests."""
import pytest
from core.context import ScanContext


def make_context(**kwargs) -> ScanContext:
    """Create a ScanContext with sensible defaults, allowing overrides."""
    defaults = dict(
        url="https://example.com",
        headers={},
        html="<html><body></body></html>",
        cookies={},
        scripts=[],
        stylesheets=[],
        js_globals=set(),
        tls=None,
        dns_records={},
        status_code=200,
    )
    defaults.update(kwargs)
    return ScanContext(**defaults)


@pytest.fixture
def empty_context():
    """A minimal ScanContext with no signals."""
    return make_context()


@pytest.fixture
def nginx_context():
    """ScanContext simulating an Nginx server response."""
    return make_context(headers={"server": "nginx/1.24.0"})


@pytest.fixture
def php_context():
    """ScanContext simulating a PHP-powered server."""
    return make_context(headers={"x-powered-by": "PHP/8.1.0"})


@pytest.fixture
def wordpress_context():
    """ScanContext with typical WordPress signals."""
    return make_context(
        headers={"server": "nginx/1.24.0", "x-powered-by": "PHP/8.1.0"},
        html=(
            '<html><head>'
            '<meta name="generator" content="WordPress 6.4.2" />'
            '<link rel="stylesheet" href="/wp-content/themes/twentytwenty/style.css" />'
            '</head><body>'
            '<script src="/wp-includes/js/jquery/jquery.min.js"></script>'
            '</body></html>'
        ),
        scripts=["https://example.com/wp-includes/js/jquery/jquery.min.js"],
        stylesheets=["https://example.com/wp-content/themes/twentytwenty/style.css"],
        cookies={"wp-settings-1": "value"},
    )
