from scanner.scorer import calculate_score

def test_perfect_score():
    res = calculate_score(
        https_enabled=True,
        http_redirect_to_https=True,
        certificate_valid=True,
        certificate_expires_in_days=30,
        missing_headers=[],
        cookie_issues=[],
        metadata_exposure=[]
    )
    assert res.score == 100
    assert res.severity == "Strong"

def test_poor_score():
    res = calculate_score(
        https_enabled=False,           # -25
        http_redirect_to_https=False,  # -10
        certificate_valid=False,       # -25 (score down to 40)
        certificate_expires_in_days=None,
        missing_headers=["Content-Security-Policy", "X-Frame-Options"], # -15 (score down to 25)
        cookie_issues=[],
        metadata_exposure=["Server header exposed: nginx"] # -3 (score down to 22)
    )
    assert res.score == 22
    assert res.severity == "Poor"

def test_score_clamping():
    res = calculate_score(
        https_enabled=False,
        http_redirect_to_https=False,
        certificate_valid=False,
        certificate_expires_in_days=None,
        missing_headers=[
            "Content-Security-Policy", "Strict-Transport-Security", 
            "X-Frame-Options", "X-Content-Type-Options", 
            "Referrer-Policy", "Permissions-Policy"
        ],
        cookie_issues=["Cookie 'session' missing Secure", "Cookie 'session' missing HttpOnly", "Cookie 'session' missing SameSite"],
        metadata_exposure=["Server exposed: apache", "X-Powered-By exposed: php"]
    )
    assert res.score == 0
    assert res.severity == "Poor"
