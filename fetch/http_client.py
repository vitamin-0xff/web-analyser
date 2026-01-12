import httpx
import logging
from typing import Optional, Dict

# Default timeout configuration (in seconds)
DEFAULT_TIMEOUT = 10.0
DEFAULT_CONNECT_TIMEOUT = 5.0

async def fetch_url(
    url: str,
    method: str = "GET",
    timeout: Optional[float] = None,
    connect_timeout: Optional[float] = None,
    headers: Optional[Dict[str, str]] = None,
    data: Optional[str] = None
):
    """
    Fetches the content of a URL with configurable timeouts and methods.
    
    Args:
        url: The URL to fetch
        method: HTTP method (GET, POST, etc.)
        timeout: Total request timeout in seconds (default: 10s)
        connect_timeout: Connection timeout in seconds (default: 5s)
        headers: Optional dictionary of HTTP headers
        data: Optional request body for POST/PUT requests
    
    Returns:
        httpx.Response object
    """
    logger = logging.getLogger(__name__)
    logger.debug(f"HTTP {method} {url} (timeout: {timeout or DEFAULT_TIMEOUT}s)")
    
    timeout_config = httpx.Timeout(
        timeout=timeout or DEFAULT_TIMEOUT,
        connect=connect_timeout or DEFAULT_CONNECT_TIMEOUT
    )
    
    try:
        async with httpx.AsyncClient(timeout=timeout_config, follow_redirects=True) as client:
            if method.upper() == "GET":
                response = await client.get(url, headers=headers)
            elif method.upper() == "POST":
                response = await client.post(url, headers=headers, content=data)
            else:
                response = await client.request(method, url, headers=headers, content=data)
            
            logger.debug(f"HTTP {response.status_code} {url} ({len(response.text)} bytes)")
            # Don't raise for status - let analyzers handle error codes
            return response
    except httpx.TimeoutException as e:
        logger.warning(f"HTTP timeout for {url}: {e}")
        raise
    except httpx.RequestError as e:
        logger.warning(f"HTTP request error for {url}: {e}")
        raise
