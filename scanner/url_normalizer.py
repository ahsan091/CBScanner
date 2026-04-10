import urllib.parse
from pydantic import BaseModel
import re

class TargetInfo(BaseModel):
    original: str
    domain: str
    base_url_http: str
    base_url_https: str

def normalize_target(target: str) -> TargetInfo:
    """
    Normalizes a given target (domain or URL) into a reliable format
    for passive scanning. Strips paths and queries.
    """
    target = target.strip()
    
    # If no schema is provided, prepend http:// to parse it properly
    if not re.match(r'^https?://', target, re.IGNORECASE):
        url = 'http://' + target
    else:
        url = target
        
    parsed = urllib.parse.urlparse(url)
    
    # The hostname is the domain we want to test
    domain = parsed.hostname
    if not domain:
        # Fallback if parsing somehow failed strangely
        domain = target.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]
    
    # Strip any www. prefix if we want a clean domain? Let's keep what the user inputted
    # as some sites only work with or without www.
    
    base_url_http = f"http://{domain}"
    base_url_https = f"https://{domain}"
    
    return TargetInfo(
        original=target,
        domain=domain,
        base_url_http=base_url_http,
        base_url_https=base_url_https
    )
