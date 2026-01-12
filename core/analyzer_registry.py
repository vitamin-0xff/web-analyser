"""Dynamic analyzer registration system."""
import logging
from typing import Dict, Type, List, Callable, Set
from models.technology import Technology

logger = logging.getLogger(__name__)


class AnalyzerRegistry:
    """Registry for dynamically discovering and instantiating analyzers."""
    
    _analyzers: Dict[str, Type] = {}
    _rule_filters: Dict[str, Callable[[List[Technology]], List[Technology]]] = {}
    _order: List[str] = []  # Preserve registration order
    _analyzer_types: Dict[str, str] = {}  # Maps analyzer name to "passive" or "active"
    
    @classmethod
    def register(cls, name: str, rule_filter: Callable[[List[Technology]], List[Technology]] = None, analyzer_type: str = "passive"):
        """Decorator to register an analyzer class.
        
        Args:
            name: Unique identifier for the analyzer (e.g., "headers", "html")
            rule_filter: Optional function to filter rules for this analyzer
            analyzer_type: Either "passive" (default) or "active" to indicate if it makes HTTP requests
        
        Example:
            @AnalyzerRegistry.register("headers", lambda rules: filter_by_types(rules, {"header"}), analyzer_type="passive")
            class HeadersAnalyzer:
                def __init__(self, rules: List[Technology]):
                    self.rules = rules
                
                async def analyze(self, context: ScanContext) -> List[Detection]:
                    ...
        """
        if analyzer_type not in ("passive", "active"):
            raise ValueError(f"analyzer_type must be 'passive' or 'active', got {analyzer_type}")
            
        def decorator(analyzer_class: Type):
            if name in cls._analyzers:
                logger.warning(f"Analyzer '{name}' already registered, overwriting")
            else:
                cls._order.append(name)
            
            cls._analyzers[name] = analyzer_class
            cls._analyzer_types[name] = analyzer_type
            if rule_filter:
                cls._rule_filters[name] = rule_filter
            
            logger.debug(f"Registered analyzer: {name} ({analyzer_type}) -> {analyzer_class.__name__}")
            return analyzer_class
        return decorator
    
    @classmethod
    def get_all_names(cls) -> List[str]:
        """Get names of all registered analyzers in registration order."""
        return cls._order.copy()
    
    @classmethod
    def get_analyzer_type(cls, name: str) -> str:
        """Get analyzer type ('passive' or 'active')."""
        return cls._analyzer_types.get(name, "passive")
    
    @classmethod
    def get_analyzers_by_type(cls, analyzer_type: str) -> List[str]:
        """Get all analyzer names of a specific type."""
        return [name for name in cls._order if cls._analyzer_types.get(name, "passive") == analyzer_type]
    
    @classmethod
    def get_analyzer_class(cls, name: str) -> Type:
        """Get analyzer class by name."""
        return cls._analyzers.get(name)
    
    @classmethod
    def instantiate_all(cls, rules: List[Technology], exclude: Set[str] = None) -> Dict[str, object]:
        """Instantiate registered analyzers with filtered rules.
        
        Args:
            rules: List of all technology detection rules
            exclude: Set of analyzer names to exclude from instantiation
        
        Returns:
            Dictionary mapping analyzer name to instantiated analyzer object
        """
        exclude = exclude or set()
        instances = {}
        
        for name in cls._order:
            if name in exclude:
                logger.info(f"Skipping excluded analyzer: {name}")
                continue
            
            analyzer_class = cls._analyzers[name]
            
            # Apply rule filter if defined
            filtered_rules = rules
            if name in cls._rule_filters:
                filtered_rules = cls._rule_filters[name](rules)
                logger.debug(f"Filtered rules for {name}: {len(filtered_rules)} technologies")
            
            # Instantiate analyzer
            instances[name] = analyzer_class(filtered_rules)
            logger.debug(f"Instantiated analyzer: {name}")
        
        return instances
    
    @classmethod
    def clear(cls):
        """Clear all registered analyzers (useful for testing)."""
        cls._analyzers.clear()
        cls._rule_filters.clear()
        cls._order.clear()
        cls._analyzer_types.clear()


def filter_by_rule_types(rules: List[Technology], allowed_types: Set[str]) -> List[Technology]:
    """Helper to filter technologies by evidence rule types.
    
    Args:
        rules: List of all technology rules
        allowed_types: Set of rule types to keep (e.g., {"header", "cookie"})
    
    Returns:
        List of Technology objects containing only matching rule types
    """
    filtered = []
    for tech in rules:
        matching_rules = [r for r in tech.evidence_rules if r.type in allowed_types]
        if matching_rules:
            filtered.append(
                Technology(
                    name=tech.name,
                    category=tech.category,
                    evidence_rules=matching_rules,
                    version=tech.version,
                )
            )
    return filtered
