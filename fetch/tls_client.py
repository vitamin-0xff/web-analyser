import ssl
import socket
from urllib.parse import urlparse

def get_tls_info(url: str):
    """
    Gets TLS certificate information for a given URL.
    """
    hostname = urlparse(url).hostname
    if not hostname:
        return None

    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return cert
    except (socket.gaierror, ConnectionRefusedError, ssl.SSLError):
        return None
