import asyncio
import argparse
import json
from core.engine import Engine

def _truncate_value(value: str, max_length: int = 200) -> str:
    """Truncate a string to max_length, adding ellipsis if truncated."""
    if not value:
        return value
    if len(value) <= max_length:
        return value
    return value[:max_length] + "..."

def _serialize_detection(d, value_max_length: int = 200):
    return {
        "name": d.name,
        "category": d.category,
        "confidence": d.confidence,
        "version": d.version,
        "evidence": {
            "type": d.evidence.type,
            "name": d.evidence.name,
            "value": _truncate_value(d.evidence.value, value_max_length),
            "pattern": d.evidence.pattern,
        },
    }

def main():
    parser = argparse.ArgumentParser(description="Website technology fingerprinting CLI")
    parser.add_argument("url", help="Target URL (e.g., https://example.com)")
    parser.add_argument("--confidence-threshold", type=float, default=0.0, help="Minimum confidence to include")
    parser.add_argument("--value-max-length", type=int, default=200, help="Maximum length for evidence values (default: 200, use 0 for unlimited)")
    args = parser.parse_args()

    async def run():
        engine = Engine()
        context = await engine.scan_url(args.url)
        detections = await engine.analyze_context(context)
        filtered = [d for d in detections if d.confidence >= args.confidence_threshold]
        # Use unlimited length if value_max_length is 0
        max_len = None if args.value_max_length == 0 else args.value_max_length
        serialized = [_serialize_detection(d, max_len or 999999) for d in filtered]
        print(json.dumps(serialized, indent=2))

    asyncio.run(run())

if __name__ == "__main__":
    main()
