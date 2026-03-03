import asyncio
import argparse
import json
import sys
import logging
from typing import List
from core.engine import Engine
from core.analyzer_registry import AnalyzerRegistry
from core.formatters import FORMATS


def _load_urls_from_file(path: str, logger: logging.Logger) -> List[str]:
    """Read one URL per line from a file, ignoring blank lines and comments."""
    try:
        with open(path) as f:
            urls = [line for line in (l.strip() for l in f) if line and not line.startswith("#")]
        if not urls:
            logger.error(f"No URLs found in {path}")
        return urls
    except FileNotFoundError:
        logger.error(f"URLs file not found: {path}")
        return []
    except Exception as e:
        logger.error(f"Error reading URLs file: {e}")
        return []


def main():
    parser = argparse.ArgumentParser(description="Website technology fingerprinting CLI")
    url_group = parser.add_mutually_exclusive_group()
    url_group.add_argument("url", nargs="?", help="Target URL (e.g., https://example.com)")
    url_group.add_argument("--urls-file", type=str, metavar="FILE", help="Path to a file containing one URL per line for batch scanning")
    parser.add_argument("--confidence-threshold", type=float, default=0.0, help="Minimum confidence to include")
    parser.add_argument("--value-max-length", type=int, default=200, help="Maximum length for evidence values (default: 200, use 0 for unlimited)")
    parser.add_argument("--log-level", type=str, default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"], help="Logging verbosity level (default: INFO)")
    parser.add_argument("--exclude", type=str, nargs="+", help="Exclude specific analyzers (e.g., --exclude html js cookies)")
    parser.add_argument("--list-analyzers", action="store_true", help="List all available analyzers and exit")
    parser.add_argument("--analyze-mode", type=str, default="passive", choices=["passive", "active", "all"], help="Analysis mode: passive (default), active (only active analyzers), or all (both)")
    parser.add_argument("--headers-file", type=str, help="Path to JSON file containing additional HTTP headers (e.g., User-Agent, Cookie, Authorization)")
    parser.add_argument("--format", type=str, default="json", choices=list(FORMATS.keys()), help="Output format: json (default), table, or csv")
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
    if not args.url and not args.urls_file:
        parser.error("A URL argument or --urls-file is required unless using --list-analyzers")
    
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
    
    # Build list of URLs to scan
    if args.urls_file:
        urls = _load_urls_from_file(args.urls_file, logger)
        if not urls:
            sys.exit(2)
    else:
        urls = [args.url]
    
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
    
    if exclude_set:
        logger.info(f"Excluding analyzers: {', '.join(sorted(exclude_set))}")
    if custom_headers:
        logger.info(f"Using custom headers: {', '.join(custom_headers.keys())}")

    # Use unlimited length if value_max_length is 0
    max_len = None if args.value_max_length == 0 else args.value_max_length

    async def scan_one(engine: Engine, url: str) -> List:
        logger.info(f"Fetching {url}...")
        try:
            context = await engine.scan_url(url)
        except Exception as e:
            logger.error(f"Failed to fetch {url}: {e}")
            sys.exit(1)
        logger.info(f"Successfully fetched {url}, status: {context.status_code}")
        logger.debug(f"HTML length: {len(context.html)} bytes, scripts: {len(context.scripts)}, stylesheets: {len(context.stylesheets)}")

        logger.info("Starting technology analysis...")
        detections = await engine.analyze_context(context)
        logger.info(f"Analysis complete, found {len(detections)} technologies before filtering")

        filtered = [d for d in detections if d.confidence >= args.confidence_threshold]
        logger.info(f"After confidence filtering: {len(filtered)} technologies")
        return filtered

    async def run():
        engine = Engine(exclude_analyzers=exclude_set, custom_headers=custom_headers)
        logger.info("Initialized analysis engine")
        formatter = FORMATS[args.format]

        if len(urls) == 1:
            # Single URL: output as before
            filtered = await scan_one(engine, urls[0])
            print(formatter(filtered, max_len or 999999))
        else:
            # Batch mode: output a mapping of URL -> results
            results = {}
            for idx, url in enumerate(urls, 1):
                logger.info(f"Scanning {url} ({idx}/{len(urls)})")
                filtered = await scan_one(engine, url)
                results[url] = filtered

            if args.format == "json":
                batch_output = {
                    url: json.loads(FORMATS["json"](detections, max_len or 999999))
                    for url, detections in results.items()
                }
                print(json.dumps(batch_output, indent=2))
            else:
                for url, detections in results.items():
                    print(f"\n=== {url} ===")
                    print(formatter(detections, max_len or 999999))

    asyncio.run(run())

if __name__ == "__main__":
    main()
