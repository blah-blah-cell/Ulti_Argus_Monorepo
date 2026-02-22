import pytest
from unittest.mock import patch, MagicMock
from datetime import date, timedelta
from hashlib import sha256
import json
import urllib.request
import urllib.error
import socket
from argus_v.licensing.verify import verify_license_file, LicenseStatus, _canonical_payload, NoRedirectHandler

def generate_payload(url="https://localhost:8080/verify"):
    expires = (date.today() + timedelta(days=30)).isoformat()
    payload = {
        "license_id": "lic-123",
        "ngo_id": "ngo-456",
        "expires_at": expires,
        "verification_url": url,
    }
    canonical = _canonical_payload(payload)
    signature = sha256(canonical.encode("utf-8")).hexdigest()
    payload["signature"] = signature
    return payload

def test_ssrf_blocked_localhost():
    payload = generate_payload("https://localhost:8080/verify")

    with patch("argus_v.licensing.verify.load_license_file", return_value=payload):
        with patch("argus_v.licensing.verify.Path.exists", return_value=True):
            # We patch build_opener to ensure no network request is made if blocked early
            with patch("urllib.request.build_opener") as mock_build_opener:
                with patch("socket.getaddrinfo") as mock_getaddrinfo:
                     mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 8080))]

                     result = verify_license_file(path="/fake", check_online=True)

                # Assertions
                assert result.status == LicenseStatus.invalid
                assert "verification_url_unsafe" in result.errors
                assert not mock_build_opener.called

def test_ssrf_blocked_private_ip():
    payload = generate_payload("https://192.168.1.10/verify")

    with patch("argus_v.licensing.verify.load_license_file", return_value=payload):
        with patch("argus_v.licensing.verify.Path.exists", return_value=True):
            with patch("urllib.request.build_opener") as mock_build_opener:
                with patch("socket.getaddrinfo") as mock_getaddrinfo:
                     mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.10", 443))]

                     result = verify_license_file(path="/fake", check_online=True)

                assert result.status == LicenseStatus.invalid
                assert "verification_url_unsafe" in result.errors
                assert not mock_build_opener.called

def test_valid_public_url():
    payload = generate_payload("https://example.com/verify")

    with patch("argus_v.licensing.verify.load_license_file", return_value=payload):
        with patch("argus_v.licensing.verify.Path.exists", return_value=True):
             with patch("socket.getaddrinfo") as mock_getaddrinfo:
                 mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

                 with patch("urllib.request.build_opener") as mock_build_opener:
                     mock_opener = MagicMock()
                     mock_resp = MagicMock()
                     mock_resp.read.return_value = json.dumps({"valid": True}).encode("utf-8")
                     mock_opener.open.return_value.__enter__.return_value = mock_resp
                     mock_build_opener.return_value = mock_opener

                     result = verify_license_file(path="/fake", check_online=True)

                     assert result.status == LicenseStatus.valid
                     assert result.verified_online is True
                     assert mock_opener.open.called

                     # Verify NoRedirectHandler was used
                     args, _ = mock_build_opener.call_args
                     assert NoRedirectHandler in args

def test_no_redirect_handler_logic():
    handler = NoRedirectHandler()
    req = MagicMock()
    req.full_url = "https://example.com/redirect"

    # Verify it raises HTTPError on 302
    with pytest.raises(urllib.error.HTTPError):
        handler.http_error_302(req, None, 302, "Found", {})

    # Verify it raises HTTPError on 301
    with pytest.raises(urllib.error.HTTPError):
        handler.http_error_301(req, None, 301, "Moved Permanently", {})

def test_ssrf_redirect_fails():
    # This test simulates what happens if open() raises HTTPError (which it will due to NoRedirectHandler)
    payload = generate_payload("https://example.com/redirect")

    with patch("argus_v.licensing.verify.load_license_file", return_value=payload):
        with patch("argus_v.licensing.verify.Path.exists", return_value=True):
             with patch("socket.getaddrinfo") as mock_getaddrinfo:
                 mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

                 with patch("urllib.request.build_opener") as mock_build_opener:
                     mock_opener = MagicMock()
                     mock_build_opener.return_value = mock_opener

                     # Simulate HTTPError 302 from opener.open (propagated from handler)
                     err = urllib.error.HTTPError("https://example.com/redirect", 302, "Found", {}, None)
                     mock_opener.open.side_effect = err

                     result = verify_license_file(path="/fake", check_online=True, offline_demo=False)

                     assert result.status == LicenseStatus.invalid
                     # The error message should capture the exception type
                     assert "verification_failed:HTTPError" in result.errors
