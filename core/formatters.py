"""Output formatters for technology detection results.

Supported formats:
- json  (default): JSON array
- table: ASCII table
- csv:   Comma-separated values
"""
import csv
import io
import json
from typing import List


def _truncate(value: str, max_length: int) -> str:
    if not value:
        return ""
    if max_length and len(value) > max_length:
        return value[:max_length] + "..."
    return value


def format_json(detections: List, value_max_length: int = 200) -> str:
    """Serialize detections to a JSON string."""
    serialized = [
        {
            "name": d.name,
            "category": d.category,
            "confidence": d.confidence,
            "version": d.version,
            "evidence": {
                "type": d.evidence.type,
                "name": d.evidence.name,
                "value": _truncate(d.evidence.value or "", value_max_length),
                "pattern": d.evidence.pattern,
            },
        }
        for d in detections
    ]
    return json.dumps(serialized, indent=2)


def format_table(detections: List, value_max_length: int = 60) -> str:
    """Format detections as a plain ASCII table."""
    if not detections:
        return "No technologies detected."

    columns = ["Technology", "Category", "Confidence", "Version", "Evidence Type"]
    rows = [
        [
            d.name,
            d.category,
            f"{d.confidence:.2f}",
            d.version or "",
            d.evidence.type,
        ]
        for d in detections
    ]

    # Calculate column widths
    widths = [len(col) for col in columns]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))

    sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    fmt = "|" + "|".join(f" {{:<{w}}} " for w in widths) + "|"

    lines = [sep, fmt.format(*columns), sep]
    for row in rows:
        lines.append(fmt.format(*row))
    lines.append(sep)

    return "\n".join(lines)


def format_csv(detections: List, value_max_length: int = 200) -> str:
    """Serialize detections to CSV."""
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(["name", "category", "confidence", "version", "evidence_type", "evidence_value"])
    for d in detections:
        writer.writerow([
            d.name,
            d.category,
            f"{d.confidence:.4f}",
            d.version or "",
            d.evidence.type,
            _truncate(d.evidence.value or "", value_max_length),
        ])
    return output.getvalue()


FORMATS = {
    "json": format_json,
    "table": format_table,
    "csv": format_csv,
}
