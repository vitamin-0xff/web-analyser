"""Tests for batch URL loading in main.py."""
import os
import pytest
import tempfile
from main import _load_urls_from_file
import logging

logger = logging.getLogger(__name__)


def test_load_urls_from_file_basic():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("https://example.com\nhttps://example.org\n")
        path = f.name
    try:
        urls = _load_urls_from_file(path, logger)
        assert urls == ["https://example.com", "https://example.org"]
    finally:
        os.unlink(path)


def test_load_urls_from_file_skips_blank_lines():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("https://example.com\n\nhttps://example.org\n\n")
        path = f.name
    try:
        urls = _load_urls_from_file(path, logger)
        assert len(urls) == 2
    finally:
        os.unlink(path)


def test_load_urls_from_file_skips_comments():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("# This is a comment\nhttps://example.com\n# Another comment\n")
        path = f.name
    try:
        urls = _load_urls_from_file(path, logger)
        assert urls == ["https://example.com"]
    finally:
        os.unlink(path)


def test_load_urls_from_file_missing_file():
    urls = _load_urls_from_file("/nonexistent/path/urls.txt", logger)
    assert urls == []


def test_load_urls_from_file_empty_file():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("")
        path = f.name
    try:
        urls = _load_urls_from_file(path, logger)
        assert urls == []
    finally:
        os.unlink(path)
