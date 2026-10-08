import pytest
from tests.conftest import extract_csrf_token
from app.database import get_db

def test_full_charging_lifecycle_end_to_end(client, app):
    """
    Comprehensive End-to-End integration test covering the entire user journey:
    Register -> Login -> Browse -> Reserve -> Charge -> Stop -> Settle -> History -> Admin Audit Trail
    """
    # 1. Register new driver
    reg_page = client.get("/auth/register")
    token_reg = extract_csrf_token(reg_page)
    client.post("/auth/register", data={
        "username": "e2edriver",
        "email": "e2e@chennai.ev",
        "password": "E2eDriverSecure2026!",
        "confirm_password": "E2eDriverSecure2026!",
        "csrf_token": token_reg
    }, follow_redirects=True)

    # 2. Browse stations
    stations_page = client.get("/user/stations?q=Chennai")
    assert b"Chennai Central EV Hub" in stations_page.data

    with app.app_context():
        db = get_db()
        station = db.execute("SELECT id FROM stations WHERE name LIKE '%Chennai Central%'").fetchone()
        station_id = station["id"]
        point = db.execute("SELECT id FROM charging_points WHERE station_id = ? AND status = 'AVAILABLE' LIMIT 1", (station_id,)).fetchone()
        point_id = point["id"]

    # 3. Reserve slot
    res_page = client.get(f"/user/reserve/{point_id}")
    token_book = extract_csrf_token(res_page)
    client.post(f"/user/reserve/{point_id}", data={
        "duration": 30,
        "csrf_token": token_book
    }, follow_redirects=True)

    # 4. Plug in and start charging
    dash_page = client.get("/user/dashboard")
    token_start = extract_csrf_token(dash_page)
    client.post(f"/user/charging/start/{point_id}", data={
        "csrf_token": token_start
    }, follow_redirects=True)

    with app.app_context():
        db = get_db()
        user = db.execute("SELECT id FROM users WHERE username = 'e2edriver'").fetchone()
        user_id = user["id"]
        sess = db.execute("SELECT id FROM charging_sessions WHERE user_id = ? AND status = 'ACTIVE'", (user_id,)).fetchone()
        session_id = sess["id"]

    # 5. Stop charging
    view_page = client.get(f"/user/charging/session/{session_id}")
    token_stop = extract_csrf_token(view_page)
    client.post(f"/user/charging/stop/{session_id}", data={
        "csrf_token": token_stop
    }, follow_redirects=True)

    # 6. Make simulated payment
    pay_page = client.get(f"/user/payment/{session_id}")
    token_pay = extract_csrf_token(pay_page)
    pay_res = client.post(f"/user/payment/{session_id}", data={
        "payment_method": "UPI",
        "csrf_token": token_pay
    }, follow_redirects=True)

    assert b"Payment Successful" in pay_res.data
    assert b"EV-TXN-" in pay_res.data

    # 7. Check driver history
    hist_page = client.get("/user/history")
    assert b"PAID" in hist_page.data
    assert b"e2e@chennai.ev" not in hist_page.data or b"Charging Sessions History" in hist_page.data

    # 8. Admin Verification
    admin_client = app.test_client()
    login_admin = admin_client.get("/auth/login")
    admin_client.post("/auth/login", data={
        "username": "admin",
        "password": "Admin@Secure2026!",
        "csrf_token": extract_csrf_token(login_admin)
    }, follow_redirects=True)

    admin_logs = admin_client.get("/admin/logs")
    assert b"USER_REGISTERED" in admin_logs.data
    assert b"RESERVATION_CREATED" in admin_logs.data
    assert b"CHARGING_STARTED" in admin_logs.data
    assert b"CHARGING_STOPPED" in admin_logs.data
    assert b"PAYMENT_COMPLETED" in admin_logs.data
