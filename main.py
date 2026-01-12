import asyncio
import argparse
import json
import logging
from core.engine import Engine
from core.analyzer_registry import AnalyzerRegistry

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
    parser.add_argument("url", nargs="?", help="Target URL (e.g., https://example.com)")
    parser.add_argument("--confidence-threshold", type=float, default=0.0, help="Minimum confidence to include")
    parser.add_argument("--value-max-length", type=int, default=200, help="Maximum length for evidence values (default: 200, use 0 for unlimited)")
    parser.add_argument("--log-level", type=str, default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"], help="Logging verbosity level (default: INFO)")
    parser.add_argument("--exclude", type=str, nargs="+", help="Exclude specific analyzers (e.g., --exclude html js cookies)")
    parser.add_argument("--list-analyzers", action="store_true", help="List all available analyzers and exit")
    parser.add_argument("--analyze-mode", type=str, default="passive", choices=["passive", "active", "all"], help="Analysis mode: passive (default), active (only active analyzers), or all (both)")
    parser.add_argument("--headers-file", type=str, help="Path to JSON file containing additional HTTP headers (e.g., User-Agent, Cookie, Authorization)")
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        level=getattr(logging, args.log_level),
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    logger = logging.getLogger(__name__)
    
    # List analyzers if requested
    if args.list_analyzers:
        print("Available analyzers:")
        print("\nPassive Analyzers (examine main page):")
        for name in sorted(AnalyzerRegistry.get_analyzers_by_type("passive")):
            print(f"  - {name}")
        print("\nActive Analyzers (make additional HTTP requests):")
        for name in sorted(AnalyzerRegistry.get_analyzers_by_type("active")):
            print(f"  - {name}")
        return
    
    # Require URL if not listing analyzers
    if not args.url:
        parser.error("URL is required unless using --list-analyzers")
    
    # Load custom headers from JSON file if provided
    custom_headers = {}
    if args.headers_file:
        try:
            with open(args.headers_file, 'r') as f:
                custom_headers = json.load(f)
                if not isinstance(custom_headers, dict):
                    logger.error("Headers file must contain a JSON object (dictionary)")
                    return
                logger.info(f"Loaded {len(custom_headers)} custom headers from {args.headers_file}")
        except FileNotFoundError:
            logger.error(f"Headers file not found: {args.headers_file}")
            return
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in headers file: {e}")
            return
        except Exception as e:
            logger.error(f"Error reading headers file: {e}")
            return
    
    # Validate and apply analyzer mode
    exclude_set = set(args.exclude) if args.exclude else set()
    
    if args.analyze_mode == "passive":
        # Exclude all active analyzers
        active_analyzers = set(AnalyzerRegistry.get_analyzers_by_type("active"))
        exclude_set.update(active_analyzers)
        logger.info("Running passive analysis only (use --analyze-mode=active or all to enable HTTP requests)")
    elif args.analyze_mode == "active":
        # Exclude all passive analyzers
        passive_analyzers = set(AnalyzerRegistry.get_analyzers_by_type("passive"))
        exclude_set.update(passive_analyzers)
        logger.info("Running active analysis only (credential probing and introspection)")
    elif args.analyze_mode == "all":
        logger.info("Running all analyzers (passive + active)")
    
    available_analyzers = set(AnalyzerRegistry.get_all_names())
    invalid_excludes = exclude_set - available_analyzers
    if invalid_excludes:
        logger.error(f"Invalid analyzer names: {', '.join(invalid_excludes)}")
        logger.info(f"Available analyzers: {', '.join(sorted(available_analyzers))}")
        return
    
    logger.info(f"Starting scan of {args.url} with confidence threshold {args.confidence_threshold}")
    if exclude_set:
        logger.info(f"Excluding analyzers: {', '.join(sorted(exclude_set))}")
    if custom_headers:
        logger.info(f"Using custom headers: {', '.join(custom_headers.keys())}")

    async def run():
        logger = logging.getLogger(__name__)
        engine = Engine(exclude_analyzers=exclude_set, custom_headers=custom_headers)
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
