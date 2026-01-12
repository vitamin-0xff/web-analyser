import dns.resolver
from typing import List, Dict, Optional

# Default DNS timeout (in seconds)
DEFAULT_DNS_TIMEOUT = 5.0

def get_dns_records(
    hostname: str,
    record_types: List[str],
    timeout: Optional[float] = None
) -> Dict[str, List[str]]:
    """
    Gets specified DNS records for a given hostname with timeout.
    
    Args:
        hostname: The hostname to query
        record_types: List of DNS record types to query (A, MX, TXT, etc.)
        timeout: DNS query timeout in seconds (default: 5s)
    
    Returns:
        Dictionary mapping record types to lists of record values
    """
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout or DEFAULT_DNS_TIMEOUT
    
    records: Dict[str, List[str]] = {}
    for record_type in record_types:
        try:
            answers = resolver.resolve(hostname, record_type)
            records[record_type] = [r.to_text() for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            records[record_type] = []
    return records
