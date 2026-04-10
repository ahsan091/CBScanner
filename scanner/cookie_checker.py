import requests
from typing import List

def check_cookies(response: requests.Response) -> List[str]:
    """
    Examines cookies returned by the server for missing security flags:
    Secure, HttpOnly, and SameSite.
    """
    issues = []
    
    if not response or not hasattr(response, 'cookies'):
        return issues
        
    for cookie in response.cookies:
        name = cookie.name
        
        # 1. Secure check
        if not cookie.secure:
            issues.append(f"Cookie '{name}' missing Secure")
            
        # Requests stores additional/non-standard attributes like HttpOnly and SameSite
        # inside the `_rest` dictionary, or they can be checked via `has_nonstandard_attr`.
        rest_lower = {}
        if hasattr(cookie, '_rest') and cookie._rest:
            rest_lower = {k.lower(): str(v) for k, v in cookie._rest.items()}
            
        # 2. HttpOnly check
        has_httponly = (
            'httponly' in rest_lower or 
            cookie.has_nonstandard_attr('HttpOnly') or 
            cookie.has_nonstandard_attr('httponly')
        )
        if not has_httponly:
            issues.append(f"Cookie '{name}' missing HttpOnly")
            
        # 3. SameSite check
        has_samesite = (
            'samesite' in rest_lower or 
            cookie.has_nonstandard_attr('SameSite') or 
            cookie.has_nonstandard_attr('samesite')
        )
        if not has_samesite:
            issues.append(f"Cookie '{name}' missing SameSite")
            
    return issues
