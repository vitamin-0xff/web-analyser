"""
Simple in-memory caching for static resources to improve performance.
"""
from typing import Any, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta


@dataclass
class CacheEntry:
    """A single cache entry with expiration."""
    value: Any
    expires_at: datetime


class ResourceCache:
    """
    Simple in-memory cache for static resources like favicon, robots.txt, etc.
    
    Useful for avoiding repeated fetches of resources that rarely change.
    """
    
    def __init__(self, default_ttl_seconds: int = 300):
        """
        Initialize the cache.
        
        Args:
            default_ttl_seconds: Default time-to-live in seconds (default: 5 minutes)
        """
        self._cache: dict[str, CacheEntry] = {}
        self.default_ttl = default_ttl_seconds
    
    def get(self, key: str) -> Optional[Any]:
        """
        Get a value from the cache.
        
        Args:
            key: The cache key
        
        Returns:
            The cached value or None if not found or expired
        """
        if key not in self._cache:
            return None
        
        entry = self._cache[key]
        if datetime.now() > entry.expires_at:
            # Expired, remove it
            del self._cache[key]
            return None
        
        return entry.value
    
    def set(self, key: str, value: Any, ttl_seconds: Optional[int] = None) -> None:
        """
        Set a value in the cache.
        
        Args:
            key: The cache key
            value: The value to cache
            ttl_seconds: Time-to-live in seconds (uses default if not specified)
        """
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl
        expires_at = datetime.now() + timedelta(seconds=ttl)
        self._cache[key] = CacheEntry(value=value, expires_at=expires_at)
    
    def invalidate(self, key: str) -> None:
        """Remove a specific key from the cache."""
        if key in self._cache:
            del self._cache[key]
    
    def clear(self) -> None:
        """Clear all cache entries."""
        self._cache.clear()
    
    def size(self) -> int:
        """Get the current number of cached entries."""
        return len(self._cache)


# Global cache instance
_global_cache = ResourceCache()


def get_cache() -> ResourceCache:
    """Get the global cache instance."""
    return _global_cache
