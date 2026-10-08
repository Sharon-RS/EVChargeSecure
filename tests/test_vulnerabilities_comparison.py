import pytest
import json

def test_demo_sqli_comparison(client):
    """Test SQLi demonstration endpoints (vulnerable vs parameterized)."""
    payload = {"input": "' OR '1'='1' --"}

    # Vulnerable mode
    vuln_res = client.post("/security-lab/demo/sqli", json={"mode": "vulnerable", **payload})
    assert vuln_res.status_code == 200
    data_vuln = vuln_res.get_json()
    assert data_vuln["mode"] == "vulnerable"
    assert "CRITICAL" in data_vuln["analysis"]

    # Secure mode
    sec_res = client.post("/security-lab/demo/sqli", json={"mode": "secure", **payload})
    assert sec_res.status_code == 200
    data_sec = sec_res.get_json()
    assert data_sec["mode"] == "secure"
    assert "SECURE" in data_sec["analysis"]

def test_demo_password_storage_comparison(client):
    """Test password storage demonstration (plaintext vs cryptographic hash)."""
    # Vulnerable mode
    vuln_res = client.post("/security-lab/demo/password-storage", json={"mode": "vulnerable", "password": "SecretPass123!"})
    data_vuln = vuln_res.get_json()
    assert data_vuln["stored_in_database"] == "SecretPass123!"

    # Secure mode
    sec_res = client.post("/security-lab/demo/password-storage", json={"mode": "secure", "password": "SecretPass123!"})
    data_sec = sec_res.get_json()
    assert data_sec["stored_in_database"] != "SecretPass123!"
    assert "pbkdf2" in data_sec["stored_in_database"] or "scrypt" in data_sec["stored_in_database"]

def test_demo_authorization_comparison(client):
    """Test RBAC demonstration (missing role check vs strict @admin_required)."""
    # Vulnerable: Regular USER can invoke
    vuln_res = client.post("/security-lab/demo/authorization", json={"mode": "vulnerable", "role": "USER"})
    assert vuln_res.status_code == 200
    assert "ALLOWED" in vuln_res.get_json()["status"]

    # Secure: Regular USER is strictly blocked
    sec_res = client.post("/security-lab/demo/authorization", json={"mode": "secure", "role": "USER"})
    assert sec_res.status_code == 403
    assert "BLOCKED" in sec_res.get_json()["status"]

def test_demo_payment_tampering_comparison(client):
    """Test payment calculation demonstration (client-controlled vs server-calculated)."""
    # Vulnerable: Client sets price to ₹1.00
    vuln_res = client.post("/security-lab/demo/payment-tampering", json={"mode": "vulnerable", "client_amount": 1.00})
    assert vuln_res.get_json()["charged_amount"] == 1.00

    # Secure: Server charges authoritative amount (₹450.00)
    sec_res = client.post("/security-lab/demo/payment-tampering", json={"mode": "secure", "client_amount": 1.00})
    assert sec_res.get_json()["charged_amount"] == 450.00

def test_demo_race_condition_comparison(client):
    """Test race condition demonstration (TOCTOU vs atomic test-and-set)."""
    vuln_res = client.post("/security-lab/demo/race-condition", json={"mode": "vulnerable", "point_id": 1})
    assert "DOUBLE BOOKING" in vuln_res.get_json()["thread_2_result"]

    sec_res = client.post("/security-lab/demo/race-condition", json={"mode": "secure", "point_id": 1})
    assert "CONFLICT" in sec_res.get_json()["thread_2_result"]

def test_demo_idor_comparison(client):
    """Test IDOR demonstration (unscoped object ID lookup vs horizontal owner verification)."""
    vuln_res = client.post("/security-lab/demo/idor", json={"mode": "vulnerable", "session_id": 42})
    assert "UNAUTHORIZED ACCESS GRANTED" in vuln_res.get_json()["status"]

    sec_res = client.post("/security-lab/demo/idor", json={"mode": "secure", "session_id": 42})
    assert "ACCESS BLOCKED" in sec_res.get_json()["status"]
