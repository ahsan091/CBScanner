import requests
from pydantic import BaseModel, ConfigDict
from typing import Optional

# 5 seconds connect, 5 seconds read as approved in the implementation plan
TIMEOUT = (5, 5)

class HttpCheckResult(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    https_enabled: bool
    http_redirect_to_https: bool
    # We store the most secure, successfully retrieved response for subsequent header/cookie checks
    primary_response: Optional[requests.Response]

def check_http_https(domain: str) -> HttpCheckResult:
    """
    Checks if HTTPS is enabled, and if HTTP redirects to HTTPS correctly.
    Returns the results and the final response object to be used by other checkers.
    """
    http_url = f"http://{domain}"
    https_url = f"https://{domain}"
    
    https_enabled = False
    http_redirect_to_https = False
    primary_response = None
    
    # 1. Check HTTP to HTTPS redirect
    try:
        http_resp = requests.get(http_url, timeout=TIMEOUT, allow_redirects=True)
        # If the final URL after redirects starts with https, it redirected properly
        if http_resp.url.startswith("https://"):
            http_redirect_to_https = True
            https_enabled = True
            primary_response = http_resp
    except requests.exceptions.RequestException:
        pass
        
    # 2. Check HTTPS directly if we don't already have an HTTPS response
    if not primary_response or not https_enabled:
        try:
            https_resp = requests.get(https_url, timeout=TIMEOUT, allow_redirects=True)
            https_enabled = True
            primary_response = https_resp
        except requests.exceptions.RequestException:
            pass

    # If both failed but HTTP somehow succeeded without redirect, keep HTTP as primary
    if not primary_response:
        try:
            # Re-fetch without redirects checking to just get the plain response
            http_resp_direct = requests.get(http_url, timeout=TIMEOUT, allow_redirects=True)
            primary_response = http_resp_direct
        except requests.exceptions.RequestException:
            pass

    return HttpCheckResult(
        https_enabled=https_enabled,
        http_redirect_to_https=http_redirect_to_https,
        primary_response=primary_response
    )
