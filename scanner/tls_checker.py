import ssl
import socket
from datetime import datetime
from pydantic import BaseModel
from typing import Optional

# Using the approved timeout internally
TIMEOUT = 5.0

class TlsCheckResult(BaseModel):
    certificate_valid: bool
    certificate_expires_in_days: Optional[int] = None
    certificate_issuer: Optional[str] = None

def check_tls(domain: str) -> TlsCheckResult:
    context = ssl.create_default_context()
    # Check validity standard
    
    cert_valid = False
    expires_in_days = None
    issuer = None
    
    try:
        with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cert_valid = True
                
                # Expiry check
                not_after_str = cert.get('notAfter')
                if not_after_str:
                    # e.g., 'May  6 23:59:59 2024 GMT'
                    not_after_date = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                    delta = not_after_date - datetime.utcnow()
                    expires_in_days = delta.days
                
                # Issuer check
                issuer_tuples = cert.get('issuer', [])
                for field in issuer_tuples:
                    for k, v in field:
                        if k == 'commonName':
                            issuer = v
                            break
                    if issuer:
                        break
                        
    except ssl.SSLCertVerificationError:
        # Certificate is invalid (expired, wrong host, self-signed, etc.)
        cert_valid = False
        # To still try and fetch cert info, we could bypass verification,
        # but for a basic passive scanner, just knowing it's invalid is often enough.
        pass
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError):
        pass

    return TlsCheckResult(
        certificate_valid=cert_valid,
        certificate_expires_in_days=expires_in_days,
        certificate_issuer=issuer
    )
