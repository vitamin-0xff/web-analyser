"""
Utility functions to validate and analyze YAML rules for duplications and inconsistencies.
"""

import yaml
from typing import List, Dict, Tuple, Any, Set
from collections import defaultdict
import os
from enum import Enum


from enum import Enum


class CheckCombination(Enum):
    """Available combinations for checking duplicates."""
    NAME_ONLY = {'name'}
    CATEGORY_ONLY = {'category'}
    NAME_CATEGORY = {'name', 'category'}
    NAME_TYPE = {'name', 'evidence_type'}
    CATEGORY_TYPE = {'category', 'evidence_type'}
    NAME_CATEGORY_TYPE = {'name', 'category', 'evidence_type'}
    ALL = {'name', 'category', 'evidence_type'}
    
    def __str__(self) -> str:
        """Return human-readable combination name."""
        names = {
            'name': 'Name',
            'category': 'Category',
            'evidence_type': 'Evidence Type'
        }
        return ' + '.join(names[f] for f in sorted(self.value))


def load_rules(rules_path: str = "rules", specific_file: str = None) -> List[Dict[str, Any]]:
    """Load all YAML rules from a directory or specific file, tracking file origins."""
    all_rules = []
    
    if specific_file:
        # Load from specific file
        filepath = os.path.join(rules_path, specific_file)
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                rules = yaml.safe_load(f)
                if isinstance(rules, list):
                    for rule in rules:
                        rule['__file__'] = specific_file
                        all_rules.append(rule)
    else:
        # Load from all files
        for filename in sorted(os.listdir(rules_path)):
            if filename.endswith('.yaml'):
                filepath = os.path.join(rules_path, filename)
                with open(filepath, 'r') as f:
                    rules = yaml.safe_load(f)
                    if isinstance(rules, list):
                        for rule in rules:
                            rule['__file__'] = filename
                            all_rules.append(rule)
    
    return all_rules


def detect_duplicates_by_combination(
    rules: List[Dict[str, Any]],
    combination: CheckCombination = CheckCombination.NAME_CATEGORY_TYPE,
    show_files: bool = False
) -> Dict[str, Tuple[str, List[Dict[str, Any]]]]:
    """
    Detect duplicate rules by specified combination of attributes.
    
    Args:
        rules: List of rule dictionaries from YAML
        combination: CheckCombination enum specifying what to check
        show_files: Whether to include file information in results
        
    Returns:
        Dictionary with combination keys and list of duplicate rules
    """
    seen = defaultdict(list)
    duplicates = defaultdict(list)
    
    for rule in rules:
        # Build the combination key based on selected attributes
        key_parts = []
        
        if 'name' in combination.value:
            key_parts.append(('name', rule.get('name', 'Unknown')))
        
        if 'category' in combination.value:
            key_parts.append(('category', rule.get('category', 'Unknown')))
        
        if 'evidence_type' in combination.value:
            # Extract evidence types
            evidence_types = set()
            if 'evidence' in rule:
                for ev in rule['evidence']:
                    evidence_types.add(ev.get('type'))
            key_parts.append(('evidence_type', frozenset(evidence_types)))
        
        # Create combination key
        combo_key = tuple(v for _, v in sorted(key_parts))
        
        seen[combo_key].append(rule)
        
        # If more than one rule with same combination, mark as duplicate
        if len(seen[combo_key]) > 1:
            duplicates[str(combo_key)] = seen[combo_key]
    
    return dict(duplicates) if duplicates else {}


def detect_cookie_overlaps(
    rules: List[Dict[str, Any]], 
    show_files: bool = False
) -> Dict[str, List[str]]:
    """
    Detect cookies used by multiple frameworks.
    
    Args:
        rules: List of rule dictionaries from YAML
        
    Returns:
        Dictionary with cookie names as keys and list of frameworks as values
    """
    cookies_map = defaultdict(list)
    
    for rule in rules:
        framework = rule.get('name', 'Unknown')
        if 'evidence' in rule:
            for ev in rule['evidence']:
                if ev.get('type') == 'cookie':
                    cookie = ev.get('name')
                    if cookie:
                        cookies_map[cookie].append(framework)
    
    # Return only cookies used by multiple frameworks
    overlaps = {
        cookie: frameworks 
        for cookie, frameworks in cookies_map.items() 
        if len(frameworks) > 1
    }
    
    return dict(overlaps) if overlaps else {}


def detect_header_overlaps(
    rules: List[Dict[str, Any]], 
    show_files: bool = False
) -> Dict[str, List[str]]:
    """
    Detect headers used by multiple frameworks.
    
    Args:
        rules: List of rule dictionaries from YAML
        
    Returns:
        Dictionary with header names as keys and list of frameworks as values
    """
    headers_map = defaultdict(list)
    
    for rule in rules:
        framework = rule.get('name', 'Unknown')
        if 'evidence' in rule:
            for ev in rule['evidence']:
                if ev.get('type') == 'header':
                    header = ev.get('name')
                    if header:
                        headers_map[header].append(framework)
    
    # Return only headers used by multiple frameworks
    overlaps = {
        header: frameworks 
        for header, frameworks in headers_map.items() 
        if len(frameworks) > 1
    }
    
    return dict(overlaps) if overlaps else {}


def detect_pattern_overlaps(
    rules: List[Dict[str, Any]], 
    show_files: bool = False
) -> Dict[str, List[str]]:
    """
    Detect HTML patterns used by multiple frameworks.
    
    Args:
        rules: List of rule dictionaries from YAML
        
    Returns:
        Dictionary with pattern strings as keys and list of frameworks as values
    """
    patterns_map = defaultdict(list)
    
    for rule in rules:
        framework = rule.get('name', 'Unknown')
        if 'evidence' in rule:
            for ev in rule['evidence']:
                if ev.get('type') == 'html_pattern':
                    pattern = ev.get('pattern')
                    if pattern:
                        patterns_map[pattern].append(framework)
    
    # Return only patterns used by multiple frameworks
    overlaps = {
        pattern: frameworks 
        for pattern, frameworks in patterns_map.items() 
        if len(frameworks) > 1
    }
    
    return dict(overlaps) if overlaps else {}


def detect_all_overlaps(
    rules: List[Dict[str, Any]], 
    show_files: bool = False
) -> Dict[str, Any]:
    """
    Detect all types of overlaps: cookies, headers, and patterns.
    
    Args:
        rules: List of rule dictionaries from YAML
        
    Returns:
        Dictionary containing all overlap types
    """
    return {
        'cookie_overlaps': detect_cookie_overlaps(rules, show_files),
        'header_overlaps': detect_header_overlaps(rules, show_files),
        'pattern_overlaps': detect_pattern_overlaps(rules, show_files),
    }


def print_validation_report(
    rules: List[Dict[str, Any]], 
    combination: CheckCombination = CheckCombination.NAME_CATEGORY_TYPE,
    show_files: bool = True,
    verbose: bool = True
) -> None:
    """
    Print a comprehensive validation report of rules.
    
    Args:
        rules: List of rule dictionaries from YAML
        combination: What combination to check for duplicates
        show_files: Whether to show file/location information
        verbose: Whether to print detailed information
    """
    print("\n" + "="*70)
    print("RULES VALIDATION REPORT")
    print("="*70)
    print(f"\nCheck Combination: {combination}")
    print(f"Show Files: {show_files}")
    
    print(f"\nTotal Rules: {len(rules)}")
    
    # Duplicates by combination
    duplicates = detect_duplicates_by_combination(rules, combination, show_files)
    if duplicates:
        print(f"\nDUPLICATE RULES (by {combination}): {len(duplicates)}")
        for combo_key, rules_list in duplicates.items():
            print(f"\n  {combo_key}")
            for rule in rules_list:
                category = rule.get('category', 'Unknown')
                evidence_count = len(rule.get('evidence', []))
                file_info = f" [{rule.get('__file__', 'unknown')}]" if show_files else ""
                print(f"    - {rule.get('name')} {category} ({evidence_count} evidences){file_info}")
    else:
        print(f"\n✓ No duplicate rules by {combination}")
    
    # Cookie overlaps
    cookie_overlaps = detect_cookie_overlaps(rules, show_files)
    if cookie_overlaps:
        print(f"\n⚠ COOKIE OVERLAPS: {len(cookie_overlaps)}")
        for cookie, frameworks in sorted(cookie_overlaps.items()):
            print(f"  '{cookie}' -> {', '.join(frameworks)}")
    else:
        print("\n✓ No cookie overlaps")
    
    # Header overlaps
    header_overlaps = detect_header_overlaps(rules, show_files)
    if header_overlaps:
        print(f"\n⚠ HEADER OVERLAPS: {len(header_overlaps)}")
        for header, frameworks in sorted(header_overlaps.items()):
            print(f"  '{header}' -> {', '.join(frameworks)}")
    else:
        print("\n✓ No header overlaps")
    
    # Pattern overlaps
    pattern_overlaps = detect_pattern_overlaps(rules, show_files)
    if pattern_overlaps:
        print(f"\n⚠ PATTERN OVERLAPS: {len(pattern_overlaps)}")
        if verbose:
            for pattern, frameworks in sorted(pattern_overlaps.items()):
                print(f"  '{pattern}' -> {', '.join(frameworks)}")
    else:
        print("\n✓ No pattern overlaps")
    
    # Statistics
    total_evidence = sum(
        len(rule.get('evidence', [])) 
        for rule in rules
    )
    frameworks = len(set(rule.get('name') for rule in rules))
    
    print(f"\nStatistics:")
    print(f"  - Unique Frameworks: {frameworks}")
    print(f"  - Total Evidence Items: {total_evidence}")
    print(f"  - Avg Evidence per Framework: {total_evidence / frameworks:.1f}")
    
    print("\n" + "="*70)


if __name__ == "__main__":
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Validate YAML rules for duplications and inconsistencies",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check duplicates by name + category + evidence type (default)
  python -m core.rules_validator
  
  # Check duplicates by name only
  python -m core.rules_validator --combination name_only
  
  # Check duplicates by name + category
  python -m core.rules_validator --combination name_category
  
  # Check duplicates by category only
  python -m core.rules_validator --combination category_only
  
  # Check duplicates by name + evidence type
  python -m core.rules_validator --combination name_type
  
  # Check duplicates by category + evidence type
  python -m core.rules_validator --combination category_type
  
  # Don't show file information
  python -m core.rules_validator --no-files
  
  # Combine options
  python -m core.rules_validator --combination name_only --no-files --no-verbose
        """
    )
    
    parser.add_argument(
        '--combination',
        default='name_category_type',
        choices=['name_only', 'category_only', 'name_category', 'name_type', 
                 'category_type', 'name_category_type', 'all'],
        help='Combination of attributes to check for duplicates (default: name_category_type)'
    )
    
    parser.add_argument(
        '--no-files',
        action='store_false',
        dest='show_files',
        default=True,
        help='Do not show file information in results'
    )
    
    parser.add_argument(
        '--no-verbose',
        action='store_false',
        dest='verbose',
        default=True,
        help='Do not show verbose details'
    )
    
    args = parser.parse_args()
    
    # Map string combination to enum
    combination_map = {
        'name_only': CheckCombination.NAME_ONLY,
        'category_only': CheckCombination.CATEGORY_ONLY,
        'name_category': CheckCombination.NAME_CATEGORY,
        'name_type': CheckCombination.NAME_TYPE,
        'category_type': CheckCombination.CATEGORY_TYPE,
        'name_category_type': CheckCombination.NAME_CATEGORY_TYPE,
        'all': CheckCombination.ALL,
    }
    
    combination = combination_map[args.combination]
    
    # Load rules from default location
    try:
        rules = load_rules()
        print_validation_report(
            rules, 
            combination=combination,
            show_files=args.show_files,
            verbose=args.verbose
        )
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
