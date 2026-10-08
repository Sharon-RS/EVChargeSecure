import pytest
from tests.conftest import extract_csrf_token
from app.database import get_db

def test_server_calculates_payment_amount_ignoring_client_tampering(user_client, app):
    """
    Test server authoritatively calculates payment amount.
    Even if client submits tampered amount (e.g. ₹0.50), the server records the authoritative database cost.
    """
    with app.app_context():
        db = get_db()
        pt = db.execute("SELECT id, tariff_per_kwh FROM charging_points WHERE status = 'AVAILABLE' LIMIT 1").fetchone()
        pt_id = pt["id"]
        tariff = pt["tariff_per_kwh"]

    # Start charging session
    dash = user_client.get("/user/dashboard")
    user_client.post(f"/user/charging/start/{pt_id}", data={"csrf_token": extract_csrf_token(dash)}, follow_redirects=True)

    with app.app_context():
        db = get_db()
        sess = db.execute("SELECT id FROM charging_sessions WHERE point_id = ? AND status = 'ACTIVE'", (pt_id,)).fetchone()
        session_id = sess["id"]

    # Stop session (server calculates energy & total_cost)
    view = user_client.get(f"/user/charging/session/{session_id}")
    stop_res = user_client.post(f"/user/charging/stop/{session_id}", data={"csrf_token": extract_csrf_token(view)}, follow_redirects=True)
    assert stop_res.status_code == 200

    with app.app_context():
        db = get_db()
        completed_sess = db.execute("SELECT * FROM charging_sessions WHERE id = ?", (session_id,)).fetchone()
        expected_cost = completed_sess["total_cost"]
        assert expected_cost > 0.0

    # Attacker attempts to pay ₹1.00 by tampering with 'amount' parameter
    pay_page = user_client.get(f"/user/payment/{session_id}")
    tampered_pay_res = user_client.post(f"/user/payment/{session_id}", data={
        "csrf_token": extract_csrf_token(pay_page),
        "payment_method": "UPI",
        "amount": "1.00"  # TAMPERED!
    }, follow_redirects=True)

    assert tampered_pay_res.status_code == 200
    assert b"Payment Successful" in tampered_pay_res.data

    # Verify that in the database, the billed amount is the authoritative expected_cost, NOT 1.00
    with app.app_context():
        db = get_db()
        payment_record = db.execute("SELECT * FROM payments WHERE session_id = ?", (session_id,)).fetchone()
        assert payment_record is not None
        assert abs(payment_record["amount"] - expected_cost) < 0.01
        assert payment_record["amount"] != 1.00
        assert payment_record["transaction_ref"].startswith("EV-TXN-")

def test_prevent_duplicate_payment_for_same_session(user_client, app):
    """Test session cannot be paid multiple times."""
    with app.app_context():
        db = get_db()
        pt = db.execute("SELECT id FROM charging_points WHERE status = 'AVAILABLE' LIMIT 1").fetchone()
        pt_id = pt["id"]

    dash = user_client.get("/user/dashboard")
    user_client.post(f"/user/charging/start/{pt_id}", data={"csrf_token": extract_csrf_token(dash)}, follow_redirects=True)

    with app.app_context():
        db = get_db()
        sess = db.execute("SELECT id FROM charging_sessions WHERE point_id = ? AND status = 'ACTIVE'", (pt_id,)).fetchone()
        session_id = sess["id"]

    view = user_client.get(f"/user/charging/session/{session_id}")
    user_client.post(f"/user/charging/stop/{session_id}", data={"csrf_token": extract_csrf_token(view)}, follow_redirects=True)

    # First payment
    pay_page = user_client.get(f"/user/payment/{session_id}")
    user_client.post(f"/user/payment/{session_id}", data={
        "csrf_token": extract_csrf_token(pay_page),
        "payment_method": "UPI"
    }, follow_redirects=True)

    # Second payment attempt on same session
    second_pay = user_client.get(f"/user/payment/{session_id}")
    assert b"already been paid" in second_pay.data
