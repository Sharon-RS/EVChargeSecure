import pytest
import concurrent.futures
from tests.conftest import extract_csrf_token
from app.database import get_db

def test_concurrent_slot_reservation_race_condition(app):
    """
    Simulate concurrent reservation attempts for the exact same charging point.
    Validates atomic test-and-set lock prevents double-booking.
    """
    with app.app_context():
        db = get_db()
        point = db.execute("SELECT id FROM charging_points WHERE status = 'AVAILABLE' LIMIT 1").fetchone()
        target_point_id = point["id"]

    # We will test using two distinct test client sessions representing Driver A (user1) and Driver B (sharon)
    client_a = app.test_client()
    res_a = client_a.get("/auth/login")
    token_a = extract_csrf_token(res_a)
    client_a.post("/auth/login", data={"username": "user1", "password": "User1@Secure2026!", "csrf_token": token_a})

    client_b = app.test_client()
    res_b = client_b.get("/auth/login")
    token_b = extract_csrf_token(res_b)
    client_b.post("/auth/login", data={"username": "sharon", "password": "Sharon@Secure2026!", "csrf_token": token_b})

    # Prepare reservation requests
    token_a_res = extract_csrf_token(client_a.get(f"/user/reserve/{target_point_id}"))
    token_b_res = extract_csrf_token(client_b.get(f"/user/reserve/{target_point_id}"))

    results = []

    def book_slot(client, token):
        return client.post(f"/user/reserve/{target_point_id}", data={
            "duration": 30,
            "csrf_token": token
        }, follow_redirects=True)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        future_a = executor.submit(book_slot, client_a, token_a_res)
        future_b = executor.submit(book_slot, client_b, token_b_res)
        results = [future_a.result(), future_b.result()]

    success_count = sum(1 for r in results if b"Slot reserved successfully" in r.data)
    conflict_count = sum(1 for r in results if b"was just reserved by another user" in r.data)

    # STRICT ASSERTION: Exactly one request MUST succeed, and exactly one MUST be rejected with conflict
    assert success_count == 1
    assert conflict_count == 1

    # Database must contain strictly 1 active reservation for this point
    with app.app_context():
        db = get_db()
        reservations = db.execute("SELECT COUNT(*) as count FROM reservations WHERE point_id = ? AND status = 'ACTIVE'", (target_point_id,)).fetchone()
        assert reservations["count"] == 1

        # Audit log must have recorded RESERVATION_CONFLICT
        conflict_log = db.execute("SELECT * FROM audit_logs WHERE event_type = 'RESERVATION_CONFLICT'").fetchone()
        assert conflict_log is not None
