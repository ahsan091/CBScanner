from typing import List, Dict

def check_exposure(headers: dict) -> List[str]:
    """
    Checks for server metadata exposure in response headers,
    specifically targeting 'Server' and 'X-Powered-By'.
    """
    exposure = []
    
    # Map lower case to original key to fetch the original value safely
    headers_lower = {k.lower(): k for k in headers.keys()}
    
    server_key = headers_lower.get('server')
    if server_key:
        exposure.append(f"Server header exposed: {headers[server_key]}")
        
    xpb_key = headers_lower.get('x-powered-by')
    if xpb_key:
        exposure.append(f"X-Powered-By exposed: {headers[xpb_key]}")
        
    return exposure
