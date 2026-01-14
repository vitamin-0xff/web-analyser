# Rules Validator Guide

A utility tool to validate YAML rules for duplications and inconsistencies across the analyzer framework.

## Overview

The `rules_validator.py` module detects:
- **Duplicate rules** by flexible combinations (name, category, evidence type)
- **Cookie overlaps** - Same cookies used by multiple frameworks
- **Header overlaps** - Same headers used by multiple frameworks  
- **Pattern overlaps** - Same HTML patterns used by multiple frameworks

## Quick Start

### Default Check (Name + Category + Evidence Type)
```bash
python -m core.rules_validator
```

### Check by Name Only
```bash
python -m core.rules_validator --combination name_only
```

### Hide File Paths
```bash
python -m core.rules_validator --no-files
```

### Minimal Output
```bash
python -m core.rules_validator --no-verbose
```

## Available Combinations

| Flag | Description | Example |
|------|-------------|---------|
| `name_only` | Check for duplicate names | Django appears in 4 files |
| `category_only` | Check for duplicate categories | "CMS" has 23 rules |
| `name_category` | Name + Category combo | Django [Web Framework] in 3 files |
| `name_type` | Name + Evidence Type combo | Django with cookie/header evidence |
| `category_type` | Category + Evidence Type combo | Web Framework with cookie evidence |
| `name_category_type` | All three (default) | Most specific check |
| `all` | All attributes combined | Same as name_category_type |

## Usage Examples

### Find all frameworks appearing multiple times
```bash
python -m core.rules_validator --combination name_only --no-files
```
**Output Shows:** 48 duplicate framework names across files

### Find where Django is defined
```bash
python -m core.rules_validator --combination name_only | grep -A 5 "Django"
```
**Output:**
```
  ('Django',)
    - Django [backend.yaml]
    - Django [backend_detection.yaml]
    - Django [cookies.yaml]
    - Django [forms.yaml]
```

### Check category-based duplicates (minimal)
```bash
python -m core.rules_validator --combination category_only --no-verbose
```
**Shows:** 46 duplicate categories with 221 total frameworks

### Detailed cookie overlap analysis
```bash
python -m core.rules_validator --combination name_category --no-files
```
**Shows:** Which frameworks share the same session cookies

## Output Interpretation

### ✅ Green Checkmarks
```
[OK] No duplicate rules by Name
[OK] No pattern overlaps
```
Indicates no issues found for that category.

### [!] Red X Marks (Duplicates)
```
[!] DUPLICATE RULES (by Name): 30
  ('Web Framework', 'Django')
    - Django Web Framework (3 evidences) [backend.yaml]
    - Django Web Framework (2 evidences) [cookies.yaml]
    - Django Web Framework (1 evidences) [forms.yaml]
```
Framework defined in multiple YAML files, with category and evidence count shown.

Format: `Name Category (N evidences) [filename]`

This helps identify:
- Which files have incomplete rules (1 evidence)
- Which categories may need consolidation (multiple duplicate entries)
- Rule coverage at a glance (3 evidences vs 1 evidence)

### [WARNING] Warning Symbols (Overlaps)
```
[WARNING] COOKIE OVERLAPS: 10
  'JSESSIONID' -> Spring Boot, Express.js
```
Same cookie indicates both frameworks, needs disambiguation.

## Common Issues & Solutions

### Understanding the Output Format

Each duplicate rule shows three key pieces of information:

```
- Django Web Framework (3 evidences) [backend.yaml]
  │      │      │          │           │
  │      │      │          │           └─ File location (with --show-files)
  │      │      │          └───────────── Number of detection patterns
  │      │      └────────────────────── Category of the technology
  │      └─────────────────────────────── Technology name
  └──────────────────────────────────────── List marker
```

**Evidence Count Interpretation:**
- **1 evidence** = Single detection method (header, cookie, etc.) - may be incomplete
- **2-3 evidences** = Multiple detection methods - more reliable
- **4+ evidences** = Comprehensive detection - very reliable

**Consolidation Strategy:**
1. Find rules with same Name + Category
2. Check evidence counts - merge higher evidence count into single rule
3. Combine detection patterns from multiple files into one definitive rule
4. Remove duplicate entries

### Issue: Too Many Duplicates
**Problem:** Framework defined in 4+ files
**Solution:** Consider consolidating rules into single file or using specific_file parameter

### Issue: Incomplete Rules
**Problem:** Rule has only 1 evidence (e.g., Flask (1 evidence) in backend.yaml)
**Solution:** Check other files for same framework, merge their evidence patterns

### Issue: Cookie Overlaps
**Problem:** JSESSIONID used by multiple frameworks
**Solution:** Add more distinctive evidence patterns (headers, patterns) to disambiguate

### Issue: Generic Headers
**Problem:** 'Server' header used by 30+ frameworks
**Solution:** This is expected - combine with other evidence types for accuracy

## Python API Usage

```python
from core.rules_validator import (
    load_rules, 
    detect_duplicates_by_combination,
    CheckCombination,
    print_validation_report
)

# Load all rules
rules = load_rules()

# Check for specific combination
duplicates = detect_duplicates_by_combination(
    rules, 
    CheckCombination.NAME_CATEGORY,
    show_files=True
)

# Print full report
print_validation_report(
    rules,
    combination=CheckCombination.NAME_CATEGORY_TYPE,
    show_files=True,
    verbose=True
)
```

## Statistics

Current state (308 total rules):
- **Unique Frameworks:** 221
- **Total Evidence Items:** 456
- **Avg Evidence per Framework:** 2.1
- **Duplicate Names:** 48
- **Duplicate Name+Category:** 44
- **Cookie Overlaps:** 10
- **Header Overlaps:** 2

## File Structure

Rules are organized across:
- `rules/backend_detection.yaml` - Backend frameworks (30 rules)
- `rules/backend.yaml` - Backend servers & frameworks
- `rules/cookies.yaml` - Cookie-based detection
- `rules/forms.yaml` - Form detection
- `rules/frontend.yaml` - Frontend detection
- `rules/active_detection.yaml` - Active probing patterns
- `rules/network.yaml` - Network-based detection
- `rules/certificate_detection.yaml` - SSL/TLS detection
- And 5+ more specialized files

## Integration with CI/CD

```bash
# Fail on duplicates
python -m core.rules_validator --combination name_category_type
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
  echo "Rule validation failed!"
  exit 1
fi
```

## Future Enhancements

- [ ] Export duplicate analysis to JSON/CSV
- [ ] Suggest rule consolidations
- [ ] Check confidence score consistency
- [ ] Detect unreachable/orphaned rules
- [ ] Validate rule syntax against schema
- [ ] Generate coverage reports per category
