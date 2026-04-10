import dns.resolver
from .schemas import DNSSummary

def check_dns(domain: str) -> DNSSummary:
    """
    Performs minimal, passive DNS resolution for standard A and AAAA records.
    Strictly adheres to passive assessment rules by avoiding subdomain brute forcing.
    """
    records = []
    
    # 1. Resolve A records
    try:
        answers = dns.resolver.resolve(domain, 'A', lifetime=5.0)
        for rdata in answers:
            records.append(rdata.to_text())
    except Exception:
        pass
        
    # 2. Resolve AAAA records
    try:
        answers_aaaa = dns.resolver.resolve(domain, 'AAAA', lifetime=5.0)
        for rdata in answers_aaaa:
            records.append(rdata.to_text())
    except Exception:
        pass
        
    return DNSSummary(a_records=records)
