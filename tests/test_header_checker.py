from scanner.header_checker import check_headers

def test_check_headers_all_missing():
    res = check_headers({})
    assert len(res.present_headers) == 0
    assert "Content-Security-Policy" in res.missing_headers
    assert "X-Frame-Options" in res.missing_headers
    assert len(res.missing_headers) == 6

def test_check_headers_mixed():
    headers = {
        "x-frame-options": "DENY",
        "Strict-Transport-Security": "max-age=31536000",
        "Server": "nginx" # Not a security defense header, ignored here
    }
    res = check_headers(headers)
    assert "X-Frame-Options" in res.present_headers
    assert "Strict-Transport-Security" in res.present_headers
    
    # Missing headers
    assert "Content-Security-Policy" in res.missing_headers
    assert "Referrer-Policy" in res.missing_headers
