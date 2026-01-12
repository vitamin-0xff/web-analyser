import dns.resolver
from typing import List, Dict

def get_dns_records(hostname: str, record_types: List[str]) -> Dict[str, List[str]]:
    """
    Gets specified DNS records for a given hostname.
    """
    records: Dict[str, List[str]] = {}
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(hostname, record_type)
            records[record_type] = [r.to_text() for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            records[record_type] = []
    return records
