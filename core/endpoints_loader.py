"""Utility module for loading endpoint and probe configuration from YAML files."""
import os
import yaml
from typing import List, Dict, Any, Optional

def load_config(config_file: str = "rules/api_endpoints.yaml") -> Dict[str, Any]:
    """
    Load configuration from a YAML file.
    
    Args:
        config_file: Path to the YAML configuration file
        
    Returns:
        Dictionary containing the configuration data
    """
    if not os.path.exists(config_file):
        return {}
    
    with open(config_file, 'r') as f:
        data = yaml.safe_load(f)
        return data if data else {}


def load_api_endpoints(rules_dir: str = "rules") -> List[str]:
    """
    Load API endpoints from configuration file.
    
    Args:
        rules_dir: Directory where api_endpoints.yaml is located
        
    Returns:
        List of API endpoint paths
    """
    config = load_config(os.path.join(rules_dir, "api_endpoints.yaml"))
    return config.get("endpoints", [])


def load_error_probe_paths(rules_dir: str = "rules") -> tuple[List[str], List[str]]:
    """
    Load error probe paths and parameters from configuration file.
    
    Args:
        rules_dir: Directory where error_probe_paths.yaml is located
        
    Returns:
        Tuple of (error_paths, error_params)
    """
    config = load_config(os.path.join(rules_dir, "error_probe_paths.yaml"))
    return config.get("error_paths", []), config.get("error_params", [])


def load_graphql_endpoints(rules_dir: str = "rules") -> tuple[List[str], str, str]:
    """
    Load GraphQL endpoints and queries from configuration file.
    
    Args:
        rules_dir: Directory where graphql_endpoints.yaml is located
        
    Returns:
        Tuple of (graphql_paths, introspection_query, simple_query)
    """
    config = load_config(os.path.join(rules_dir, "graphql_endpoints.yaml"))
    return (
        config.get("graphql_paths", []),
        config.get("introspection_query", ""),
        config.get("simple_query", "")
    )
