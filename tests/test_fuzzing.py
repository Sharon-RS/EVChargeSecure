import pytest
from tests.conftest import extract_csrf_token

FUZZ_PAYLOADS = [
    "' OR '1'='1' --",
    "'; DROP TABLE users; --",
    "admin'/*",
    "<script>alert('XSS')</script>",
    "javascript:/*--></title></style>\"/><svg/onload=alert`1`>",
    "A" * 2000,
    "%s%s%s%s%n",
    "{{ 7 * 7 }}",
    "${7*7}",
    "\x00\x00\x00",
    "../../../etc/passwd",
    "..\\..\\windows\\win.ini",
    "null",
    "undefined",
    "NaN",
    "⚡🚗🔋🔥💥"
]

def test_fuzz_registration_inputs(client):
    """Fuzz registration inputs to verify input sanitization and zero-crash robustness."""
    for payload in FUZZ_PAYLOADS:
        res = client.get("/auth/register")
        token = extract_csrf_token(res)

        fuzz_res = client.post("/auth/register", data={
            "username": payload[:35],
            "email": f"test_{payload[:10]}@domain.com",
            "password": payload[:30],
            "confirm_password": payload[:30],
            "csrf_token": token
        }, follow_redirects=True)

        # Robustness guarantee: Server must NEVER throw 500 uncaught internal server error
        assert fuzz_res.status_code in [200, 400]

def test_fuzz_login_inputs(client):
    """Fuzz login credentials with injection payloads."""
    for payload in FUZZ_PAYLOADS:
        res = client.get("/auth/login")
        token = extract_csrf_token(res)

        fuzz_res = client.post("/auth/login", data={
            "username": payload,
            "password": payload,
            "csrf_token": token
        }, follow_redirects=True)

        assert fuzz_res.status_code in [200, 400]

def test_fuzz_station_search(user_client):
    """Fuzz station locator search query."""
    for payload in FUZZ_PAYLOADS:
        search_res = user_client.get(f"/user/stations?q={payload}")
        assert search_res.status_code == 200
        # Assert page rendered cleanly without database exception leak
        assert b"EV Charging Network Stations" in search_res.data

def test_fuzz_nonexistent_and_malformed_object_ids(user_client):
    """Test boundary and malformed IDs on resource endpoints."""
    bad_ids = [-1, 0, 99999999, "abc", "null", "1' OR '1'='1"]
    for bad_id in bad_ids:
        res = user_client.get(f"/user/stations/{bad_id}")
        assert res.status_code in [200, 302, 404]

        res2 = user_client.get(f"/user/reserve/{bad_id}")
        assert res2.status_code in [200, 302, 404]
