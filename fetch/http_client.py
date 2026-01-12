import httpx
from typing import Optional

# Default timeout configuration (in seconds)
DEFAULT_TIMEOUT = 10.0
DEFAULT_CONNECT_TIMEOUT = 5.0

async def fetch_url(
    url: str,
    timeout: Optional[float] = None,
    connect_timeout: Optional[float] = None
):
    """
    Fetches the content of a URL with configurable timeouts.
    
    Args:
        url: The URL to fetch
        timeout: Total request timeout in seconds (default: 10s)
        connect_timeout: Connection timeout in seconds (default: 5s)
    
    Returns:
        httpx.Response object
    """
    timeout_config = httpx.Timeout(
        timeout=timeout or DEFAULT_TIMEOUT,
        connect=connect_timeout or DEFAULT_CONNECT_TIMEOUT
    )
    
    async with httpx.AsyncClient(timeout=timeout_config, follow_redirects=True) as client:
        response = await client.get(url)
        response.raise_for_status()
        return response
