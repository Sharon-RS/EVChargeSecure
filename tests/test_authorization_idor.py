import pytest
from tests.conftest import extract_csrf_token
from app.database import get_db

def test_rbac_admin_endpoint_blocked_for_normal_user(user_client, app):
    """Test standard USER role is denied access to admin endpoints and audit log records violation."""
    res = user_client.get("/admin/dashboard", follow_redirects=True)
    assert b"Access denied: Administrator privileges required" in res.data or res.status_code == 403

    # Check audit log for AUTHORIZATION_FAILURE
    with app.app_context():
        db = get_db()
        violation = db.execute("SELECT * FROM audit_logs WHERE event_type = 'AUTHORIZATION_FAILURE'").fetchone()
        assert violation is not None

def test_rbac_admin_allowed_access(admin_client):
    """Test ADMIN role successfully accesses admin hub."""
    res = admin_client.get("/admin/dashboard")
    assert res.status_code == 200
    assert b"Fleet Command &amp; Infrastructure Overview" in res.data or b"Fleet Command" in res.data

def test_idor_prevent_canceling_another_users_reservation(app):
    """Test user cannot manipulate reservation ID to cancel another user's reservation."""
    # User 1 creates a reservation
    client_user1 = app.test_client()
    res1 = client_user1.get("/auth/login")
    token1 = extract_csrf_token(res1)
    client_user1.post("/auth/login", data={"username": "user1", "password": "User1@Secure2026!", "csrf_token": token1})

    with app.app_context():
        db = get_db()
        pt = db.execute("SELECT id FROM charging_points WHERE status = 'AVAILABLE' LIMIT 1").fetchone()
        pt_id = pt["id"]

    res_book = client_user1.get(f"/user/reserve/{pt_id}")
    client_user1.post(f"/user/reserve/{pt_id}", data={"duration": 30, "csrf_token": extract_csrf_token(res_book)})

    with app.app_context():
        db = get_db()
        user1_res = db.execute("SELECT id FROM reservations WHERE point_id = ? AND status = 'ACTIVE'", (pt_id,)).fetchone()
        target_res_id = user1_res["id"]

    # Attacker (Sharon) attempts to cancel User 1's reservation
    client_sharon = app.test_client()
    res2 = client_sharon.get("/auth/login")
    token2 = extract_csrf_token(res2)
    client_sharon.post("/auth/login", data={"username": "sharon", "password": "Sharon@Secure2026!", "csrf_token": token2})

    dash = client_sharon.get("/user/dashboard")
    token_sharon = extract_csrf_token(dash)
    attack_res = client_sharon.post(f"/user/reservations/{target_res_id}/cancel", data={"csrf_token": token_sharon}, follow_redirects=True)

    assert b"Reservation not found or access denied" in attack_res.data

    # Ensure reservation is STILL ACTIVE
    with app.app_context():
        db = get_db()
        still_active = db.execute("SELECT status FROM reservations WHERE id = ?", (target_res_id,)).fetchone()
        assert still_active["status"] == "ACTIVE"

def test_idor_prevent_viewing_other_users_charging_session(app):
    """Test user cannot access live session view belonging to another driver."""
    client_user1 = app.test_client()
    client_user1.post("/auth/login", data={
        "username": "user1", "password": "User1@Secure2026!",
        "csrf_token": extract_csrf_token(client_user1.get("/auth/login"))
    })

    with app.app_context():
        db = get_db()
        pt = db.execute("SELECT id FROM charging_points WHERE status = 'AVAILABLE' LIMIT 1").fetchone()
        pt_id = pt["id"]

    dash = client_user1.get("/user/dashboard")
    client_user1.post(f"/user/charging/start/{pt_id}", data={"csrf_token": extract_csrf_token(dash)}, follow_redirects=True)

    with app.app_context():
        db = get_db()
        sess = db.execute("SELECT id FROM charging_sessions WHERE point_id = ? AND status = 'ACTIVE'", (pt_id,)).fetchone()
        session_id = sess["id"]

    # Sharon attempts to view User 1's session
    client_sharon = app.test_client()
    client_sharon.post("/auth/login", data={
        "username": "sharon", "password": "Sharon@Secure2026!",
        "csrf_token": extract_csrf_token(client_sharon.get("/auth/login"))
    })

    attack_view = client_sharon.get(f"/user/charging/session/{session_id}", follow_redirects=True)
    assert b"Charging session not found or unauthorized" in attack_view.data
