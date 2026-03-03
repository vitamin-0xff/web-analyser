"""Tests for the rules loader and version utility functions."""
import pytest
from rules.rules_loader import load_rules
from models.technology import Technology, EvidenceRule
from core.version_utils import (
    extract_version_from_url,
    extract_version_from_string,
    normalize_version,
)


# ---------------------------------------------------------------------------
# Rules loader
# ---------------------------------------------------------------------------

def test_load_rules_returns_list():
    rules = load_rules()
    assert isinstance(rules, list)
    assert len(rules) > 0


def test_load_rules_all_have_name_and_category():
    rules = load_rules()
    for tech in rules:
        assert tech.name, f"Technology missing name: {tech}"
        assert tech.category, f"Technology missing category: {tech.name}"


def test_load_rules_all_have_evidence():
    rules = load_rules()
    for tech in rules:
        assert len(tech.evidence_rules) > 0, f"{tech.name} has no evidence rules"


def test_load_rules_evidence_confidence_in_range():
    rules = load_rules()
    for tech in rules:
        for rule in tech.evidence_rules:
            assert 0.0 <= rule.confidence <= 1.0, (
                f"{tech.name} rule has confidence {rule.confidence} out of [0, 1]"
            )


def test_load_rules_evidence_type_not_empty():
    rules = load_rules()
    for tech in rules:
        for rule in tech.evidence_rules:
            assert rule.type, f"{tech.name} has an evidence rule without a type"


def test_load_rules_technology_object_types():
    """Each loaded object must be a Technology with EvidenceRule children."""
    rules = load_rules()
    for tech in rules:
        assert isinstance(tech, Technology)
        for rule in tech.evidence_rules:
            assert isinstance(rule, EvidenceRule)


# ---------------------------------------------------------------------------
# Version utilities
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("url,expected", [
    ("https://cdn.example.com/jquery-3.6.0.min.js", "3.6.0"),
    ("https://cdn.example.com/bootstrap/5.1.3/bootstrap.min.css", "5.1.3"),
    ("https://example.com/style.css?ver=4.9.1", "4.9.1"),
    ("https://example.com/noversion.js", None),
])
def test_extract_version_from_url(url, expected):
    assert extract_version_from_url(url) == expected


@pytest.mark.parametrize("text,tech,expected", [
    ("WordPress 6.4.2", "WordPress", "6.4.2"),
    ("React v18.2.0", "React", "18.2.0"),
    ("some text without version", "Unknown", None),
])
def test_extract_version_from_string(text, tech, expected):
    assert extract_version_from_string(text, tech) == expected


@pytest.mark.parametrize("raw,expected", [
    ("v1.2.3", "1.2.3"),
    ("1.2.x", "1.2"),
    ("1.2.3-beta", "1.2.3-beta"),
    (None, None),
    ("", None),
])
def test_normalize_version(raw, expected):
    assert normalize_version(raw) == expected
