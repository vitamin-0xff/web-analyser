import asyncio
import argparse
import json
import logging
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
    parser.add_argument("--log-level", type=str, default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"], help="Logging verbosity level (default: INFO)")
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        level=getattr(logging, args.log_level),
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    logger = logging.getLogger(__name__)
    logger.info(f"Starting scan of {args.url} with confidence threshold {args.confidence_threshold}")

    async def run():
        logger = logging.getLogger(__name__)
        engine = Engine()
        logger.info("Initialized analysis engine")
        
        logger.info(f"Fetching {args.url}...")
        context = await engine.scan_url(args.url)
        logger.info(f"Successfully fetched {args.url}, status: {context.status_code}")
        logger.debug(f"HTML length: {len(context.html)} bytes, scripts: {len(context.scripts)}, stylesheets: {len(context.stylesheets)}")
        
        logger.info("Starting technology analysis...")
        detections = await engine.analyze_context(context)
        logger.info(f"Analysis complete, found {len(detections)} technologies before filtering")
        
        filtered = [d for d in detections if d.confidence >= args.confidence_threshold]
        logger.info(f"After confidence filtering: {len(filtered)} technologies")
        
        # Use unlimited length if value_max_length is 0
        max_len = None if args.value_max_length == 0 else args.value_max_length
        serialized = [_serialize_detection(d, max_len or 999999) for d in filtered]
        
        logger.info("Serializing detections to JSON")
        print(json.dumps(serialized, indent=2))

    asyncio.run(run())

if __name__ == "__main__":
    main()
