import asyncio
import argparse
import json
from core.engine import Engine

def _serialize_detection(d):
    return {
        "name": d.name,
        "category": d.category,
        "confidence": d.confidence,
        "version": d.version,
        "evidence": {
            "type": d.evidence.type,
            "name": d.evidence.name,
            "value": d.evidence.value,
            "pattern": d.evidence.pattern,
        },
    }

def main():
    parser = argparse.ArgumentParser(description="Website technology fingerprinting CLI")
    parser.add_argument("url", help="Target URL (e.g., https://example.com)")
    parser.add_argument("--confidence-threshold", type=float, default=0.0, help="Minimum confidence to include")
    args = parser.parse_args()

    async def run():
        engine = Engine()
        context = await engine.scan_url(args.url)
        detections = await engine.analyze_context(context)
        filtered = [d for d in detections if d.confidence >= args.confidence_threshold]
        print(json.dumps([_serialize_detection(d) for d in filtered], indent=2))

    asyncio.run(run())

if __name__ == "__main__":
    main()
