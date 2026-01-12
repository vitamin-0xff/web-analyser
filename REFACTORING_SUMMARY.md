# Hard-Coded URLs Refactoring Summary

## Overview
Successfully extracted all hard-coded URLs from active analyzers and moved them to YAML configuration files for better maintainability and flexibility.

## Changes Made

### 1. New YAML Configuration Files Created

#### **rules/api_endpoints.yaml**
- Contains common API endpoint paths (25 endpoints)
- Used by `analyzers/api_probe.py`
- Includes: `/api`, `/api/v1`, `/api/v2`, `/api/v3`, `/v1`, `/v2`, `/v3`, `/rest`, `/api/rest`, `/api/docs`, `/api/swagger.json`, `/api/openapi.json`, `/swagger.json`, `/openapi.json`, `/api-docs`, `/docs`, `/.well-known/api`, `/health`, `/api/health`, `/status`, `/api/status`, `/version`, `/api/version`

#### **rules/error_probe_paths.yaml**
- Contains paths to trigger errors (9 paths) and query parameters (4 params)
- Used by `analyzers/error_probe.py`
- Error paths: `/api/nonexistent`, `/nonexistent.php`, `/nonexistent.asp`, `/nonexistent.aspx`, `/nonexistent.jsp`, `/test/error`, `/.env`, `/config.php`, `/admin/config`
- Error params: `?id=999999`, `?debug=true`, `?error=1`, `?test=invalid`

#### **rules/graphql_endpoints.yaml**
- Contains GraphQL endpoint paths (9 paths) and introspection queries
- Used by `analyzers/graphql.py`
- Includes: `/graphql`, `/api/graphql`, `/v1/graphql`, `/query`, `/api/query`, `/gql`, `/api/gql`, `/graphql/v1`, `/api/v1/graphql`
- Contains introspection and simple query templates

### 2. New Utility Module Created

#### **core/endpoints_loader.py**
New module with functions to load endpoint configurations:
- `load_api_endpoints(rules_dir="rules")` - Load API endpoints list
- `load_error_probe_paths(rules_dir="rules")` - Load error probe paths and params
- `load_graphql_endpoints(rules_dir="rules")` - Load GraphQL endpoints and queries
- `load_config(config_file)` - Generic config loader

### 3. Analyzer Refactoring

#### **analyzers/api_probe.py**
- Removed hard-coded `API_ENDPOINTS` list
- Added import: `from core.endpoints_loader import load_api_endpoints`
- Updated `analyze()` method to call `load_api_endpoints()` at runtime

#### **analyzers/error_probe.py**
- Removed hard-coded `ERROR_PATHS` and `ERROR_PARAMS` lists
- Added import: `from core.endpoints_loader import load_error_probe_paths`
- Updated `analyze()` method to call `load_error_probe_paths()` at runtime

#### **analyzers/graphql.py**
- Removed hard-coded `GRAPHQL_PATHS`, `INTROSPECTION_QUERY`, and `SIMPLE_QUERY`
- Added import: `from core.endpoints_loader import load_graphql_endpoints`
- Updated `analyze()` method to call `load_graphql_endpoints()` at runtime

## Benefits

✅ **Easier Configuration**: Endpoints can be modified without changing code  
✅ **Better Maintainability**: Centralized configuration management  
✅ **Extensibility**: Users can add new endpoints by editing YAML files  
✅ **Consistency**: All endpoint configurations follow the same pattern  
✅ **Dynamic Loading**: Endpoints loaded at runtime from YAML  

## File Structure

```
rules/
├── api_endpoints.yaml          # NEW: API endpoints
├── error_probe_paths.yaml      # NEW: Error probe paths
├── graphql_endpoints.yaml      # NEW: GraphQL endpoints
└── ...

core/
├── endpoints_loader.py         # NEW: Configuration loader utility
└── ...

analyzers/
├── api_probe.py               # REFACTORED: Now uses YAML
├── error_probe.py             # REFACTORED: Now uses YAML
├── graphql.py                 # REFACTORED: Now uses YAML
└── ...
```

## Usage Example

To add a new API endpoint, simply edit `rules/api_endpoints.yaml`:

```yaml
endpoints:
  - /api
  - /api/v1
  - /my/custom/endpoint  # NEW ENDPOINT
```

The next run will automatically include the new endpoint without any code changes.
