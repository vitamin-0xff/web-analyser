"""Tests for output formatters (json, table, csv)."""
import json
import pytest
from core.formatters import format_json, format_table, format_csv
from models.detection import Detection, Evidence


def _det(name: str, category: str = "Framework", confidence: float = 0.9,
         version: str = None, evidence_type: str = "header",
         evidence_value: str = "some-value") -> Detection:
    return Detection(
        name=name,
        category=category,
        confidence=confidence,
        version=version,
        evidence=Evidence(type=evidence_type, value=evidence_value),
    )


# ---------------------------------------------------------------------------
# JSON formatter
# ---------------------------------------------------------------------------

def test_format_json_empty():
    result = format_json([])
    assert json.loads(result) == []


def test_format_json_returns_valid_json():
    detections = [_det("Nginx", confidence=0.8)]
    result = format_json(detections)
    parsed = json.loads(result)
    assert len(parsed) == 1
    assert parsed[0]["name"] == "Nginx"
    assert parsed[0]["confidence"] == 0.8


def test_format_json_evidence_included():
    detections = [_det("PHP", evidence_type="header", evidence_value="PHP/8.1")]
    result = format_json(detections)
    parsed = json.loads(result)
    assert parsed[0]["evidence"]["type"] == "header"
    assert parsed[0]["evidence"]["value"] == "PHP/8.1"


def test_format_json_value_truncated():
    long_value = "x" * 500
    detections = [_det("Nginx", evidence_value=long_value)]
    result = format_json(detections, value_max_length=10)
    parsed = json.loads(result)
    assert len(parsed[0]["evidence"]["value"]) <= 13  # 10 + "..."


def test_format_json_version_included():
    detections = [_det("jQuery", version="3.6.0")]
    result = format_json(detections)
    parsed = json.loads(result)
    assert parsed[0]["version"] == "3.6.0"


# ---------------------------------------------------------------------------
# Table formatter
# ---------------------------------------------------------------------------

def test_format_table_empty():
    result = format_table([])
    assert "No technologies detected" in result


def test_format_table_contains_technology_name():
    detections = [_det("Nginx")]
    result = format_table(detections)
    assert "Nginx" in result


def test_format_table_contains_headers():
    detections = [_det("Nginx")]
    result = format_table(detections)
    assert "Technology" in result
    assert "Confidence" in result


def test_format_table_multiple_rows():
    detections = [_det("Nginx"), _det("WordPress", category="CMS")]
    result = format_table(detections)
    assert "Nginx" in result
    assert "WordPress" in result


# ---------------------------------------------------------------------------
# CSV formatter
# ---------------------------------------------------------------------------

def test_format_csv_empty():
    result = format_csv([])
    lines = result.strip().splitlines()
    # Only the header row
    assert len(lines) == 1
    assert "name" in lines[0]


def test_format_csv_header_row():
    result = format_csv([])
    header = result.strip().splitlines()[0]
    assert "name" in header
    assert "category" in header
    assert "confidence" in header


def test_format_csv_data_row():
    detections = [_det("Nginx", confidence=0.9)]
    result = format_csv(detections)
    lines = result.strip().splitlines()
    assert len(lines) == 2  # header + 1 data row
    assert "Nginx" in lines[1]


def test_format_csv_multiple_rows():
    detections = [_det("Nginx"), _det("WordPress")]
    result = format_csv(detections)
    lines = result.strip().splitlines()
    assert len(lines) == 3  # header + 2 data rows
