from pydantic import BaseModel
from typing import List, Optional

class ScoreResult(BaseModel):
    score: int
    severity: str
    recommendations: List[str]

def calculate_score(
    https_enabled: bool,
    http_redirect_to_https: bool,
    certificate_valid: bool,
    certificate_expires_in_days: Optional[int],
    missing_headers: List[str],
    cookie_issues: List[str],
    metadata_exposure: List[str]
) -> ScoreResult:
    score = 100
    recs = []

    # Transport / TLS
    if not https_enabled:
        score -= 25
        recs.append("Enable HTTPS to secure traffic in transit.")
    
    if not certificate_valid:
        score -= 25
        recs.append("Install or renew a valid TLS certificate.")
        
    if certificate_expires_in_days is not None and certificate_expires_in_days < 14:
        score -= 10
        recs.append(f"Renew TLS certificate, expires in {certificate_expires_in_days} days.")
        
    if not http_redirect_to_https:
        score -= 10
        recs.append("Enforce HTTP to HTTPS redirection.")

    # Headers
    h_lower = [h.lower() for h in missing_headers]
    if 'content-security-policy' in h_lower:
        score -= 10
        recs.append("Implement a Content-Security-Policy header to reduce client-side injection risks.")
    if 'strict-transport-security' in h_lower:
        score -= 10
        recs.append("Enable Strict-Transport-Security (HSTS) for persistent HTTPS enforcement.")
    if 'x-frame-options' in h_lower:
        score -= 5
        recs.append("Add X-Frame-Options to prevent Clickjacking.")
    if 'x-content-type-options' in h_lower:
        score -= 5
        recs.append("Add X-Content-Type-Options to prevent MIME-sniffing.")
    if 'referrer-policy' in h_lower:
        score -= 4
        recs.append("Add a Referrer-Policy header to control data leakage across origins.")
    if 'permissions-policy' in h_lower:
        score -= 3
        recs.append("Add a Permissions-Policy header to restrict powerful browser features.")

    # Cookies
    has_secure_issue = any("missing secure" in issue.lower() for issue in cookie_issues)
    has_httponly_issue = any("missing httponly" in issue.lower() for issue in cookie_issues)
    has_samesite_issue = any("missing samesite" in issue.lower() for issue in cookie_issues)
    
    if has_secure_issue:
        score -= 5
        recs.append("Ensure all sensitive cookies are marked Secure.")
    if has_httponly_issue:
        score -= 5
        recs.append("Ensure all sensitive cookies are marked HttpOnly.")
    if has_samesite_issue:
        score -= 4
        recs.append("Ensure all sensitive cookies employ a SameSite policy.")

    # Exposure
    has_server_exposure = any("server" in issue.lower() for issue in metadata_exposure)
    has_xpb_exposure = any("x-powered-by" in issue.lower() for issue in metadata_exposure)
    
    if has_server_exposure:
        score -= 3
        recs.append("Obfuscate or remove the exposed Server header.")
    if has_xpb_exposure:
        score -= 4
        recs.append("Remove the X-Powered-By header to hide backend technology.")

    # Clamp Score
    score = max(0, min(100, score))

    # Severity bands
    if score >= 85:
        severity = "Strong"
    elif score >= 70:
        severity = "Moderate"
    elif score >= 50:
        severity = "Weak"
    else:
        severity = "Poor"

    return ScoreResult(
        score=score,
        severity=severity,
        recommendations=recs
    )
