import ssl
import socket
import logging
from urllib.parse import urlparse
from typing import Optional

# Default TLS connection timeout (in seconds)
DEFAULT_TLS_TIMEOUT = 5.0

def get_tls_info(url: str, timeout: Optional[float] = None):
    """
    Gets TLS certificate information for a given URL with timeout.
    
    Args:
        url: The URL to get TLS info for
        timeout: Connection timeout in seconds (default: 5s)
    
    Returns:
        Certificate dictionary or None if connection fails
    """
    logger = logging.getLogger(__name__)
    hostname = urlparse(url).hostname
    if not hostname:
        logger.debug(f"No hostname extracted from {url}")
        return None

    logger.debug(f"TLS certificate fetch for {hostname}:{443}")
    context = ssl.create_default_context()
    timeout_value = timeout or DEFAULT_TLS_TIMEOUT
    
    try:
        with socket.create_connection((hostname, 443), timeout=timeout_value) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get('issuer', []))
                logger.debug(f"TLS certificate found for {hostname} (issuer: {issuer.get('organizationName', 'N/A')})")
                return cert
    except (socket.gaierror, ConnectionRefusedError, ssl.SSLError, socket.timeout) as e:
        logger.debug(f"TLS error for {hostname}: {type(e).__name__}")
