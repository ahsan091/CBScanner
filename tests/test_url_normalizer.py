from scanner.url_normalizer import normalize_target

def test_normalize_raw_domain():
    res = normalize_target("example.com")
    assert res.domain == "example.com"
    assert res.base_url_http == "http://example.com"
    assert res.base_url_https == "https://example.com"

def test_normalize_http_url():
    res = normalize_target("http://example.com/some/path")
    assert res.domain == "example.com"
    assert res.base_url_http == "http://example.com"
    assert res.base_url_https == "https://example.com"

def test_normalize_https_url_with_query():
    res = normalize_target("https://sub.domain.com/index.php?id=1")
    assert res.domain == "sub.domain.com"
    assert res.base_url_http == "http://sub.domain.com"
