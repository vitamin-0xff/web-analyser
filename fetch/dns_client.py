import dns.resolver
import logging
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
    logger = logging.getLogger(__name__)
    logger.debug(f"DNS query for {hostname}: {record_types}")
    
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout or DEFAULT_DNS_TIMEOUT
    
    records: Dict[str, List[str]] = {}
    for record_type in record_types:
        try:
            answers = resolver.resolve(hostname, record_type)
            records[record_type] = [r.to_text() for r in answers]
            logger.debug(f"DNS {record_type} {hostname}: {len(records[record_type])} records")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout) as e:
            records[record_type] = []
            logger.debug(f"DNS {record_type} {hostname}: no records ({type(e).__name__})")
