import math
import uuid
from datetime import datetime, timezone, timedelta
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, abort, jsonify
from app.database import get_db
from app.security import login_required, csrf_protect, log_audit_event

user_bp = Blueprint("user", __name__, url_prefix="/user")

@user_bp.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    user_id = session["user_id"]

    # Active reservation for this user
    active_reservation = db.execute("""
        SELECT r.*, cp.identifier as point_name, cp.connector_type, cp.tariff_per_kwh, s.name as station_name
        FROM reservations r
        JOIN charging_points cp ON r.point_id = cp.id
        JOIN stations s ON cp.station_id = s.id
        WHERE r.user_id = ? AND r.status = 'ACTIVE'
        ORDER BY r.created_at DESC LIMIT 1
    """, (user_id,)).fetchone()

    # Active charging session for this user
    active_session = db.execute("""
        SELECT cs.*, cp.identifier as point_name, cp.max_power_kw, cp.tariff_per_kwh, s.name as station_name
        FROM charging_sessions cs
        JOIN charging_points cp ON cs.point_id = cp.id
        JOIN stations s ON cp.station_id = s.id
        WHERE cs.user_id = ? AND cs.status = 'ACTIVE'
        ORDER BY cs.start_time DESC LIMIT 1
    """, (user_id,)).fetchone()

    # Pending payment for completed session
    pending_payment = db.execute("""
        SELECT cs.*, cp.identifier as point_name, s.name as station_name
        FROM charging_sessions cs
        JOIN charging_points cp ON cs.point_id = cp.id
        JOIN stations s ON cp.station_id = s.id
        LEFT JOIN payments p ON p.session_id = cs.id
        WHERE cs.user_id = ? AND cs.status = 'COMPLETED' AND p.id IS NULL
        ORDER BY cs.end_time DESC LIMIT 1
    """, (user_id,)).fetchone()

    # Summary statistics for user
    stats = db.execute("""
        SELECT 
            COUNT(DISTINCT cs.id) as total_sessions,
            COALESCE(SUM(cs.energy_kwh), 0.0) as total_energy,
            COALESCE(SUM(p.amount), 0.0) as total_spent
        FROM charging_sessions cs
        LEFT JOIN payments p ON p.session_id = cs.id AND p.status = 'PAID'
        WHERE cs.user_id = ? AND cs.status = 'COMPLETED'
    """, (user_id,)).fetchone()

    # Available stations sample
    stations = db.execute("""
        SELECT s.*, 
            COUNT(cp.id) as total_points,
            SUM(CASE WHEN cp.status = 'AVAILABLE' THEN 1 ELSE 0 END) as available_points
        FROM stations s
        LEFT JOIN charging_points cp ON s.id = cp.station_id
        GROUP BY s.id
        LIMIT 4
    """).fetchall()

    return render_template(
        "user/dashboard.html",
        active_reservation=active_reservation,
        active_session=active_session,
        pending_payment=pending_payment,
        stats=stats,
        stations=stations
    )

@user_bp.route("/stations")
@login_required
def stations():
    query = request.args.get("q", "").strip()
    db = get_db()

    if query:
        # Parameterized query with wildcard search
        wildcard = f"%{query}%"
        stations_list = db.execute("""
            SELECT s.*, 
                COUNT(cp.id) as total_points,
                SUM(CASE WHEN cp.status = 'AVAILABLE' THEN 1 ELSE 0 END) as available_points
            FROM stations s
            LEFT JOIN charging_points cp ON s.id = cp.station_id
            WHERE s.name LIKE ? OR s.location LIKE ? OR s.address LIKE ?
            GROUP BY s.id
        """, (wildcard, wildcard, wildcard)).fetchall()
    else:
        stations_list = db.execute("""
            SELECT s.*, 
                COUNT(cp.id) as total_points,
                SUM(CASE WHEN cp.status = 'AVAILABLE' THEN 1 ELSE 0 END) as available_points
            FROM stations s
            LEFT JOIN charging_points cp ON s.id = cp.station_id
            GROUP BY s.id
        """).fetchall()

    return render_template("user/stations.html", stations=stations_list, search_query=query)

@user_bp.route("/stations/<int:station_id>")
@login_required
def station_detail(station_id):
    db = get_db()
    station = db.execute("SELECT * FROM stations WHERE id = ?", (station_id,)).fetchone()
    if not station:
        flash("Station not found.", "warning")
        return redirect(url_for("user.stations"))

    points = db.execute("""
        SELECT * FROM charging_points 
        WHERE station_id = ?
        ORDER BY identifier ASC
    """, (station_id,)).fetchall()

    return render_template("user/station_detail.html", station=station, points=points)

@user_bp.route("/reserve/<int:point_id>", methods=["GET", "POST"])
@login_required
@csrf_protect
def reserve_point(point_id):
    db = get_db()
    user_id = session["user_id"]

    point = db.execute("""
        SELECT cp.*, s.name as station_name, s.location
        FROM charging_points cp
        JOIN stations s ON cp.station_id = s.id
        WHERE cp.id = ?
    """, (point_id,)).fetchone()

    if not point:
        flash("Charging point not found.", "warning")
        return redirect(url_for("user.stations"))

    # Check if user already has an active reservation
    existing_res = db.execute("""
        SELECT id FROM reservations 
        WHERE user_id = ? AND status = 'ACTIVE'
    """, (user_id,)).fetchone()

    if existing_res:
        flash("You already have an active reservation. Please complete or cancel it before booking another.", "warning")
        return redirect(url_for("user.dashboard"))

    if request.method == "POST":
        duration_minutes = int(request.form.get("duration", 30))
        if duration_minutes not in [15, 30, 45, 60]:
            duration_minutes = 30

        start_dt = datetime.now(timezone.utc)
        end_dt = start_dt + timedelta(minutes=duration_minutes)

        # SECURE CONCURRENCY CONTROL:
        # Atomic test-and-set query to avoid race conditions and double bookings.
        # Only updates status if current status is strictly 'AVAILABLE'.
        cursor = db.cursor()
        cursor.execute("""
            UPDATE charging_points 
            SET status = 'RESERVED' 
            WHERE id = ? AND status = 'AVAILABLE'
        """, (point_id,))

        if cursor.rowcount == 0:
            # Another concurrent request already reserved or occupied this point
            log_audit_event(
                "RESERVATION_CONFLICT",
                f"Concurrent reservation race avoided: User {session['username']} attempted to reserve occupied point {point['identifier']} (ID {point_id})",
                severity="WARNING"
            )
            flash("This charging point was just reserved by another user or is no longer available. Please select another slot.", "danger")
            return redirect(url_for("user.station_detail", station_id=point["station_id"]))

        # Successfully locked point: record reservation
        cursor.execute("""
            INSERT INTO reservations (user_id, point_id, start_time, end_time, status)
            VALUES (?, ?, ?, ?, 'ACTIVE')
        """, (user_id, point_id, start_dt.isoformat(), end_dt.isoformat()))
        res_id = cursor.lastrowid
        db.commit()

        log_audit_event(
            "RESERVATION_CREATED",
            f"Reservation #{res_id} created by user {session['username']} for point {point['identifier']} ({duration_minutes} mins)",
            severity="INFO"
        )

        flash(f"Slot reserved successfully at {point['station_name']} ({point['identifier']})!", "success")
        return redirect(url_for("user.dashboard"))

    return render_template("user/reserve.html", point=point)

@user_bp.route("/reservations/<int:reservation_id>/cancel", methods=["POST"])
@login_required
@csrf_protect
def cancel_reservation(reservation_id):
    db = get_db()
    user_id = session["user_id"]

    # IDOR PROTECTION: Ensure reservation strictly belongs to the authenticated user
    reservation = db.execute("""
        SELECT * FROM reservations 
        WHERE id = ? AND user_id = ?
    """, (reservation_id, user_id)).fetchone()

    if not reservation:
        log_audit_event(
            "AUTHORIZATION_FAILURE",
            f"IDOR attempt: User {session['username']} attempted to cancel reservation #{reservation_id} owned by another user",
            severity="SECURITY_ALERT"
        )
        flash("Reservation not found or access denied.", "danger")
        return redirect(url_for("user.dashboard"))

    if reservation["status"] != "ACTIVE":
        flash("This reservation is no longer active.", "info")
        return redirect(url_for("user.dashboard"))

    cursor = db.cursor()
    cursor.execute("UPDATE reservations SET status = 'CANCELLED' WHERE id = ?", (reservation_id,))
    cursor.execute("UPDATE charging_points SET status = 'AVAILABLE' WHERE id = ?", (reservation["point_id"],))
    db.commit()

    log_audit_event(
        "RESERVATION_CANCELLED",
        f"Reservation #{reservation_id} cancelled by user {session['username']}",
        severity="INFO"
    )

    flash("Reservation cancelled. The charging point is now available for others.", "info")
    return redirect(url_for("user.dashboard"))

@user_bp.route("/charging/start/<int:point_id>", methods=["POST"])
@login_required
@csrf_protect
def start_charging(point_id):
    db = get_db()
    user_id = session["user_id"]

    point = db.execute("SELECT * FROM charging_points WHERE id = ?", (point_id,)).fetchone()
    if not point:
        flash("Charging point not found.", "warning")
        return redirect(url_for("user.dashboard"))

    # User may have an active reservation for this point
    active_res = db.execute("""
        SELECT * FROM reservations 
        WHERE user_id = ? AND point_id = ? AND status = 'ACTIVE'
    """, (user_id, point_id)).fetchone()

    # If point is not reserved by this user, verify it is AVAILABLE
    if not active_res and point["status"] != "AVAILABLE":
        flash("Charging point is not available for immediate session.", "warning")
        return redirect(url_for("user.dashboard"))

    cursor = db.cursor()
    cursor.execute("UPDATE charging_points SET status = 'CHARGING' WHERE id = ?", (point_id,))
    if active_res:
        cursor.execute("UPDATE reservations SET status = 'COMPLETED' WHERE id = ?", (active_res["id"],))

    now_iso = datetime.now(timezone.utc).isoformat()
    cursor.execute("""
        INSERT INTO charging_sessions (user_id, point_id, reservation_id, start_time, energy_kwh, total_cost, status)
        VALUES (?, ?, ?, ?, 0.0, 0.0, 'ACTIVE')
    """, (user_id, point_id, active_res["id"] if active_res else None, now_iso))
    session_id = cursor.lastrowid
    db.commit()

    log_audit_event(
        "CHARGING_STARTED",
        f"Charging session #{session_id} initiated at point {point['identifier']} by user {session['username']}",
        severity="INFO"
    )

    flash("Charging session started! High voltage handshake established.", "success")
    return redirect(url_for("user.charging_view", session_id=session_id))

@user_bp.route("/charging/session/<int:session_id>")
@login_required
def charging_view(session_id):
    db = get_db()
    user_id = session["user_id"]

    # IDOR PROTECTION: Ensure session belongs to current user
    charging_session = db.execute("""
        SELECT cs.*, cp.identifier as point_name, cp.connector_type, cp.max_power_kw, cp.tariff_per_kwh,
               s.name as station_name, s.location
        FROM charging_sessions cs
        JOIN charging_points cp ON cs.point_id = cp.id
        JOIN stations s ON cp.station_id = s.id
        WHERE cs.id = ? AND cs.user_id = ?
    """, (session_id, user_id)).fetchone()

    if not charging_session:
        log_audit_event(
            "AUTHORIZATION_FAILURE",
            f"IDOR attempt: User {session['username']} attempted to view charging session #{session_id}",
            severity="SECURITY_ALERT"
        )
        flash("Charging session not found or unauthorized.", "danger")
        return redirect(url_for("user.dashboard"))

    return render_template("user/charging.html", session_data=charging_session)

@user_bp.route("/charging/stop/<int:session_id>", methods=["POST"])
@login_required
@csrf_protect
def stop_charging(session_id):
    db = get_db()
    user_id = session["user_id"]

    # IDOR PROTECTION
    charging_session = db.execute("""
        SELECT cs.*, cp.max_power_kw, cp.tariff_per_kwh
        FROM charging_sessions cs
        JOIN charging_points cp ON cs.point_id = cp.id
        WHERE cs.id = ? AND cs.user_id = ?
    """, (session_id, user_id)).fetchone()

    if not charging_session:
        log_audit_event(
            "AUTHORIZATION_FAILURE",
            f"IDOR attempt: User {session['username']} attempted to stop charging session #{session_id}",
            severity="SECURITY_ALERT"
        )
        flash("Session not found or access denied.", "danger")
        return redirect(url_for("user.dashboard"))

    if charging_session["status"] != "ACTIVE":
        flash("This charging session has already been completed.", "info")
        return redirect(url_for("user.payment_view", session_id=session_id))

    # Calculate simulated energy & duration
    end_dt = datetime.now(timezone.utc)
    try:
        start_dt = datetime.fromisoformat(charging_session["start_time"])
    except Exception:
        start_dt = end_dt - timedelta(minutes=15)

    duration_seconds = max(60, (end_dt - start_dt).total_seconds())
    duration_hours = duration_seconds / 3600.0

    # Realistic EV energy formula: power (kW) * time * average charging curve factor (0.85)
    # Ensure minimum simulated charge of 12.5 kWh for demonstration realism
    calculated_kwh = round(max(12.5, charging_session["max_power_kw"] * duration_hours * 0.85), 2)

    # CRUCIAL SECURITY CONTROL:
    # SERVER STRICTLY CALCULATES TOTAL COST! Client never dictates payment amount.
    server_calculated_cost = round(calculated_kwh * charging_session["tariff_per_kwh"], 2)

    cursor = db.cursor()
    cursor.execute("""
        UPDATE charging_sessions 
        SET end_time = ?, energy_kwh = ?, total_cost = ?, status = 'COMPLETED'
        WHERE id = ?
    """, (end_dt.isoformat(), calculated_kwh, server_calculated_cost, session_id))

    # Set point status back to AVAILABLE
    cursor.execute("UPDATE charging_points SET status = 'AVAILABLE' WHERE id = ?", (charging_session["point_id"],))
    db.commit()

    log_audit_event(
        "CHARGING_STOPPED",
        f"Charging session #{session_id} stopped. Consumed: {calculated_kwh} kWh. Server calculated amount: INR {server_calculated_cost}",
        severity="INFO"
    )

    flash(f"Charging complete! Consumed {calculated_kwh} kWh. Total payable: ₹{server_calculated_cost:.2f}", "success")
    return redirect(url_for("user.payment_view", session_id=session_id))

@user_bp.route("/payment/<int:session_id>", methods=["GET", "POST"])
@login_required
@csrf_protect
def payment_view(session_id):
    db = get_db()
    user_id = session["user_id"]

    # IDOR PROTECTION: User can only pay for their own session
    charging_session = db.execute("""
        SELECT cs.*, cp.identifier as point_name, cp.tariff_per_kwh, s.name as station_name
        FROM charging_sessions cs
        JOIN charging_points cp ON cs.point_id = cp.id
        JOIN stations s ON cp.station_id = s.id
        WHERE cs.id = ? AND cs.user_id = ?
    """, (session_id, user_id)).fetchone()

    if not charging_session:
        log_audit_event(
            "AUTHORIZATION_FAILURE",
            f"IDOR attempt: User {session['username']} attempted payment for unauthorized session #{session_id}",
            severity="SECURITY_ALERT"
        )
        flash("Charging session not found or unauthorized.", "danger")
        return redirect(url_for("user.dashboard"))

    # Check if payment already recorded
    existing_payment = db.execute("SELECT * FROM payments WHERE session_id = ?", (session_id,)).fetchone()
    if existing_payment:
        flash("This charging session has already been paid.", "info")
        return render_template("user/receipt.html", payment=existing_payment, session_data=charging_session)

    if request.method == "POST":
        payment_method = request.form.get("payment_method", "UPI")
        if payment_method not in ["UPI", "CREDIT_CARD", "DEBIT_CARD", "FASTAG_EV"]:
            payment_method = "UPI"

        # VULNERABILITY MITIGATION:
        # Client input 'amount' is completely ignored.
        # The amount is derived directly from the authoritative database record.
        authorized_amount = charging_session["total_cost"]

        # If client tampered with amount parameter in an exploit attempt:
        tampered_amount = request.form.get("amount")
        if tampered_amount is not None:
            try:
                tampered_val = float(tampered_amount)
                if abs(tampered_val - authorized_amount) > 0.01:
                    log_audit_event(
                        "PAYMENT_TAMPERING_DETECTED",
                        f"Client supplied tampered amount ₹{tampered_val} vs authoritative server cost ₹{authorized_amount}. Server enforced authoritative value.",
                        severity="SECURITY_ALERT"
                    )
            except ValueError:
                pass

        txn_ref = f"EV-TXN-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"

        cursor = db.cursor()
        cursor.execute("""
            INSERT INTO payments (session_id, user_id, amount, currency, payment_method, status, transaction_ref)
            VALUES (?, ?, ?, 'INR', ?, 'PAID', ?)
        """, (session_id, user_id, authorized_amount, payment_method, txn_ref))
        payment_id = cursor.lastrowid
        db.commit()

        log_audit_event(
            "PAYMENT_COMPLETED",
            f"Payment #{payment_id} processed for session #{session_id} by user {session['username']}. Ref: {txn_ref}, Amount: INR {authorized_amount}",
            severity="INFO"
        )

        payment_record = db.execute("SELECT * FROM payments WHERE id = ?", (payment_id,)).fetchone()
        flash(f"Payment of ₹{authorized_amount:.2f} successful! Transaction Reference: {txn_ref}", "success")
        return render_template("user/receipt.html", payment=payment_record, session_data=charging_session)

    return render_template("user/payment.html", session_data=charging_session)

@user_bp.route("/history")
@login_required
def history():
    db = get_db()
    user_id = session["user_id"]

    # IDOR PROTECTION: Retrieve only records where user_id matches session
    history_records = db.execute("""
        SELECT cs.*, cp.identifier as point_name, cp.connector_type, s.name as station_name,
               p.amount as paid_amount, p.status as payment_status, p.transaction_ref, p.created_at as paid_at
        FROM charging_sessions cs
        JOIN charging_points cp ON cs.point_id = cp.id
        JOIN stations s ON cp.station_id = s.id
        LEFT JOIN payments p ON p.session_id = cs.id
        WHERE cs.user_id = ?
        ORDER BY cs.start_time DESC
    """, (user_id,)).fetchall()

    reservations_list = db.execute("""
        SELECT r.*, cp.identifier as point_name, s.name as station_name
        FROM reservations r
        JOIN charging_points cp ON r.point_id = cp.id
        JOIN stations s ON cp.station_id = s.id
        WHERE r.user_id = ?
        ORDER BY r.created_at DESC
    """, (user_id,)).fetchall()

    return render_template("user/history.html", records=history_records, reservations=reservations_list)

@user_bp.route("/receipt/<int:payment_id>")
@login_required
def receipt(payment_id):
    db = get_db()
    user_id = session["user_id"]

    # IDOR PROTECTION: User can only view their own payment receipt
    payment = db.execute("""
        SELECT * FROM payments 
        WHERE id = ? AND user_id = ?
    """, (payment_id, user_id)).fetchone()

    if not payment:
        log_audit_event(
            "AUTHORIZATION_FAILURE",
            f"IDOR attempt: User {session['username']} attempted to view payment receipt #{payment_id}",
            severity="SECURITY_ALERT"
        )
        flash("Payment receipt not found or access denied.", "danger")
        return redirect(url_for("user.history"))

    session_data = db.execute("""
        SELECT cs.*, cp.identifier as point_name, cp.connector_type, cp.tariff_per_kwh,
               s.name as station_name, s.location
        FROM charging_sessions cs
        JOIN charging_points cp ON cs.point_id = cp.id
        JOIN stations s ON cp.station_id = s.id
        WHERE cs.id = ?
    """, (payment["session_id"],)).fetchone()

    return render_template("user/receipt.html", payment=payment, session_data=session_data)
