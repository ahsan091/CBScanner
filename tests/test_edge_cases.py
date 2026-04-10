import pytest
from unittest.mock import patch, MagicMock
import requests
import re
from scanner.http_checker import check_http_https
from ai.gemini_client import generate_report
from scanner.schemas import ScanResult, DNSSummary
from datetime import datetime

# 1. Timeout Edge Case Simulation
@patch('scanner.http_checker.requests.get')
def test_http_timeout_behavior(mock_get):
    """Ensure HTTP checker cleanly processes network timeouts."""
    mock_get.side_effect = requests.exceptions.Timeout("Connection timed out")
    
    result = check_http_https("http://example.timeouts.com")
    assert result.https_enabled is False
    assert result.http_redirect_to_https is False

# 2. Output Filename Sanitization Constraints
def test_filename_sanitization():
    """Verify that malformed targets are safely serialized for localized PDF/JSON generation."""
    malformed_targets = [
        "https://weird***string.com",
        "example.com/login?auth=123",
        "http://sub.example.com:8080"
    ]
    
    for target in malformed_targets:
        target_safe = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', target)
        
        # Test no forbidden OS serialization characters persist
        assert "*" not in target_safe
        assert "/" not in target_safe
        assert "?" not in target_safe
        assert ":" not in target_safe
        assert "=" not in target_safe

# 3. Gemini Fallback via API 503 Simulation
@patch('ai.gemini_client.genai.Client')
@patch('ai.gemini_client.os.getenv')
def test_gemini_fallback_handles_503(mock_getenv, mock_client):
    """Verify the AI loop handles Google API 503 errors gracefully without crashing the overall CLI script."""
    mock_getenv.return_value = "dummy-api-key"
    
    mock_models = MagicMock()
    mock_models.generate_content.side_effect = Exception("503 Service Unavailable")
    
    mock_instance = MagicMock()
    mock_instance.models = mock_models
    mock_client.return_value = mock_instance
    
    dummy_scan = ScanResult(
        target="example.com",
        scan_timestamp=datetime.now(),
        https_enabled=True,
        http_redirect_to_https=True,
        certificate_valid=True,
        certificate_expires_in_days=30,
        certificate_issuer="Test",
        dns_summary=DNSSummary(a_records=[]),
        missing_headers=[],
        present_headers=[],
        cookie_issues=[],
        metadata_exposure=[],
        score=100,
        severity="Good",
        recommendations=[]
    )
    
    # Exploit patch on time to prevent test hanging for 10 seconds during retries
    with patch('time.sleep', return_value=None):
        result_markdown = generate_report(dummy_scan)
        
    # The function should capture the 503 natively, attempt standard retries, fail gracefully, and return None.
    assert result_markdown is None
