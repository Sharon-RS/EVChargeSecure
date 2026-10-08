import pytest
from tests.conftest import extract_csrf_token
from app.database import get_db

def test_reserve_available_point(user_client, app):
    """Test successful slot booking for an available charging terminal."""
    # Find an available point ID
    with app.app_context():
        db = get_db()
        point = db.execute("SELECT id FROM charging_points WHERE status = 'AVAILABLE' LIMIT 1").fetchone()
        point_id = point["id"]

    res = user_client.get(f"/user/reserve/{point_id}")
    assert res.status_code == 200
    token = extract_csrf_token(res)

    book_res = user_client.post(f"/user/reserve/{point_id}", data={
        "duration": 30,
        "csrf_token": token
    }, follow_redirects=True)

    assert book_res.status_code == 200
    assert b"Slot reserved successfully" in book_res.data

    with app.app_context():
        db = get_db()
        updated_pt = db.execute("SELECT status FROM charging_points WHERE id = ?", (point_id,)).fetchone()
        assert updated_pt["status"] == "RESERVED"

def test_prevent_multiple_concurrent_reservations(user_client, app):
    """Test that a driver cannot hoard multiple active slot reservations."""
    with app.app_context():
        db = get_db()
        avail_points = db.execute("SELECT id FROM charging_points WHERE status = 'AVAILABLE' LIMIT 2").fetchall()
        p1 = avail_points[0]["id"]
        p2 = avail_points[1]["id"]

    # Book first point
    res1 = user_client.get(f"/user/reserve/{p1}")
    token1 = extract_csrf_token(res1)
    user_client.post(f"/user/reserve/{p1}", data={"duration": 30, "csrf_token": token1}, follow_redirects=True)

    # Try booking second point
    res2 = user_client.get(f"/user/reserve/{p2}")
    token2 = extract_csrf_token(res2)
    second_booking = user_client.post(f"/user/reserve/{p2}", data={"duration": 30, "csrf_token": token2}, follow_redirects=True)

    assert b"already have an active reservation" in second_booking.data

def test_cancel_reservation_frees_point(user_client, app):
    """Test cancellation marks reservation CANCELLED and frees point back to AVAILABLE."""
    with app.app_context():
        db = get_db()
        pt = db.execute("SELECT id FROM charging_points WHERE status = 'AVAILABLE' LIMIT 1").fetchone()
        pt_id = pt["id"]

    # Book point
    res = user_client.get(f"/user/reserve/{pt_id}")
    token = extract_csrf_token(res)
    user_client.post(f"/user/reserve/{pt_id}", data={"duration": 30, "csrf_token": token}, follow_redirects=True)

    # Retrieve reservation ID
    with app.app_context():
        db = get_db()
        reservation = db.execute("SELECT id FROM reservations WHERE point_id = ? AND status = 'ACTIVE'", (pt_id,)).fetchone()
        res_id = reservation["id"]

    # Cancel reservation
    dash_res = user_client.get("/user/dashboard")
    token_dash = extract_csrf_token(dash_res)
    cancel_res = user_client.post(f"/user/reservations/{res_id}/cancel", data={"csrf_token": token_dash}, follow_redirects=True)

    assert b"Reservation cancelled" in cancel_res.data

    with app.app_context():
        db = get_db()
        point_after = db.execute("SELECT status FROM charging_points WHERE id = ?", (pt_id,)).fetchone()
        assert point_after["status"] == "AVAILABLE"
