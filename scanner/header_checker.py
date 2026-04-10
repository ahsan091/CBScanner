from pydantic import BaseModel
from typing import List, Dict

class HeaderCheckResult(BaseModel):
    present_headers: List[str]
    missing_headers: List[str]

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

def check_headers(headers: dict) -> HeaderCheckResult:
    """
    Evaluates response headers for the presence of standard defense-in-depth mechanisms.
    """
    present = []
    missing = []
    
    # Normalize keys to lower case for reliable matching
    headers_lower = {k.lower(): str(v) for k, v in headers.items()}
    
    for header in SECURITY_HEADERS:
        if header.lower() in headers_lower:
            present.append(header)
        else:
            missing.append(header)
            
    return HeaderCheckResult(
        present_headers=present,
        missing_headers=missing
    )
