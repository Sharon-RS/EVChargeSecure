from datetime import datetime, timezone
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from app.database import get_db
from app.security import admin_required, csrf_protect, log_audit_event

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

@admin_bp.route("/dashboard")
@admin_required
def dashboard():
    db = get_db()

    total_stations = db.execute("SELECT COUNT(*) as count FROM stations").fetchone()["count"]
    total_points = db.execute("SELECT COUNT(*) as count FROM charging_points").fetchone()["count"]
    active_points = db.execute("SELECT COUNT(*) as count FROM charging_points WHERE status = 'CHARGING'").fetchone()["count"]
    available_points = db.execute("SELECT COUNT(*) as count FROM charging_points WHERE status = 'AVAILABLE'").fetchone()["count"]
    maintenance_points = db.execute("SELECT COUNT(*) as count FROM charging_points WHERE status = 'MAINTENANCE'").fetchone()["count"]
    
    total_energy = db.execute("SELECT COALESCE(SUM(energy_kwh), 0.0) as val FROM charging_sessions WHERE status = 'COMPLETED'").fetchone()["val"]
    total_revenue = db.execute("SELECT COALESCE(SUM(amount), 0.0) as val FROM payments WHERE status = 'PAID'").fetchone()["val"]

    recent_sessions = db.execute("""
        SELECT cs.*, u.username, cp.identifier as point_name, s.name as station_name
        FROM charging_sessions cs
        JOIN users u ON cs.user_id = u.id
        JOIN charging_points cp ON cs.point_id = cp.id
        JOIN stations s ON cp.station_id = s.id
        ORDER BY cs.start_time DESC LIMIT 5
    """).fetchall()

    recent_logs = db.execute("""
        SELECT * FROM audit_logs 
        ORDER BY timestamp DESC LIMIT 6
    """).fetchall()

    stations_status = db.execute("""
        SELECT s.*,
            COUNT(cp.id) as total_pts,
            SUM(CASE WHEN cp.status = 'AVAILABLE' THEN 1 ELSE 0 END) as avail_pts,
            SUM(CASE WHEN cp.status = 'CHARGING' THEN 1 ELSE 0 END) as charging_pts,
            SUM(CASE WHEN cp.status = 'MAINTENANCE' THEN 1 ELSE 0 END) as maint_pts
        FROM stations s
        LEFT JOIN charging_points cp ON s.id = cp.station_id
        GROUP BY s.id
    """).fetchall()

    return render_template(
        "admin/dashboard.html",
        total_stations=total_stations,
        total_points=total_points,
        active_points=active_points,
        available_points=available_points,
        maintenance_points=maintenance_points,
        total_energy=total_energy,
        total_revenue=total_revenue,
        recent_sessions=recent_sessions,
        recent_logs=recent_logs,
        stations_status=stations_status
    )

@admin_bp.route("/stations", methods=["GET", "POST"])
@admin_required
@csrf_protect
def manage_stations():
    db = get_db()

    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        location = (request.form.get("location") or "").strip()
        address = (request.form.get("address") or "").strip()
        status = request.form.get("status", "ACTIVE")

        if not name or not location or not address:
            flash("All station fields are required.", "danger")
        else:
            cursor = db.cursor()
            cursor.execute("""
                INSERT INTO stations (name, location, address, total_points, status)
                VALUES (?, ?, ?, 0, ?)
            """, (name, location, address, status))
            station_id = cursor.lastrowid
            db.commit()

            log_audit_event(
                "ADMIN_ACTION",
                f"Admin {session['username']} created station: '{name}' (ID {station_id})",
                severity="INFO"
            )
            flash(f"Station '{name}' added successfully.", "success")
            return redirect(url_for("admin.manage_stations"))

    stations_list = db.execute("""
        SELECT s.*, COUNT(cp.id) as count_points
        FROM stations s
        LEFT JOIN charging_points cp ON s.id = cp.station_id
        GROUP BY s.id
        ORDER BY s.id ASC
    """).fetchall()

    return render_template("admin/stations_manage.html", stations=stations_list)

@admin_bp.route("/points", methods=["GET", "POST"])
@admin_required
@csrf_protect
def manage_points():
    db = get_db()

    if request.method == "POST":
        station_id = request.form.get("station_id")
        identifier = (request.form.get("identifier") or "").strip()
        connector_type = request.form.get("connector_type", "CCS2 (DC Fast)")
        max_power_kw = request.form.get("max_power_kw")
        tariff_per_kwh = request.form.get("tariff_per_kwh")

        try:
            sid = int(station_id)
            power = float(max_power_kw)
            tariff = float(tariff_per_kwh)

            if power < 3.0 or power > 350.0:
                flash("Power limit must be between 3.0 kW and 350.0 kW.", "danger")
            elif tariff < 1.0 or tariff > 100.0:
                flash("Tariff must be between ₹1.00 and ₹100.00 per kWh.", "danger")
            elif not identifier:
                flash("Charging point identifier is required.", "danger")
            else:
                cursor = db.cursor()
                cursor.execute("""
                    INSERT INTO charging_points (station_id, identifier, connector_type, max_power_kw, status, tariff_per_kwh)
                    VALUES (?, ?, ?, ?, 'AVAILABLE', ?)
                """, (sid, identifier, connector_type, power, tariff))
                
                # Update total points count on station
                cursor.execute("""
                    UPDATE stations 
                    SET total_points = (SELECT COUNT(*) FROM charging_points WHERE station_id = ?)
                    WHERE id = ?
                """, (sid, sid))
                
                db.commit()

                log_audit_event(
                    "ADMIN_ACTION",
                    f"Admin {session['username']} added charging point {identifier} ({power} kW, ₹{tariff}/kWh) to station #{sid}",
                    severity="INFO"
                )
                flash(f"Charging point {identifier} configured successfully.", "success")
                return redirect(url_for("admin.manage_points"))
        except (ValueError, TypeError):
            flash("Invalid numeric value provided for power limit or tariff.", "danger")

    points_list = db.execute("""
        SELECT cp.*, s.name as station_name 
        FROM charging_points cp
        JOIN stations s ON cp.station_id = s.id
        ORDER BY cp.station_id, cp.identifier
    """).fetchall()

    stations_list = db.execute("SELECT id, name FROM stations WHERE status = 'ACTIVE'").fetchall()

    return render_template("admin/points_manage.html", points=points_list, stations=stations_list)

@admin_bp.route("/points/<int:point_id>/update", methods=["POST"])
@admin_required
@csrf_protect
def update_point(point_id):
    db = get_db()
    point = db.execute("SELECT * FROM charging_points WHERE id = ?", (point_id,)).fetchone()
    if not point:
        flash("Charging point not found.", "warning")
        return redirect(url_for("admin.manage_points"))

    try:
        max_power = float(request.form.get("max_power_kw", point["max_power_kw"]))
        tariff = float(request.form.get("tariff_per_kwh", point["tariff_per_kwh"]))
        status = request.form.get("status", point["status"])

        if max_power < 3.0 or max_power > 350.0:
            flash("Power limit must be between 3.0 kW and 350.0 kW.", "danger")
            return redirect(url_for("admin.manage_points"))

        if status not in ["AVAILABLE", "RESERVED", "CHARGING", "MAINTENANCE", "OFFLINE"]:
            flash("Invalid status specified.", "danger")
            return redirect(url_for("admin.manage_points"))

        cursor = db.cursor()
        cursor.execute("""
            UPDATE charging_points 
            SET max_power_kw = ?, tariff_per_kwh = ?, status = ?
            WHERE id = ?
        """, (max_power, tariff, status, point_id))
        db.commit()

        log_audit_event(
            "ADMIN_ACTION",
            f"Admin {session['username']} updated point #{point_id} ({point['identifier']}): Power={max_power}kW, Tariff=₹{tariff}/kWh, Status={status}",
            severity="INFO"
        )
        flash(f"Charging point {point['identifier']} updated successfully.", "success")
    except ValueError:
        flash("Invalid numerical values provided.", "danger")

    return redirect(url_for("admin.manage_points"))

@admin_bp.route("/maintenance", methods=["GET", "POST"])
@admin_required
@csrf_protect
def maintenance():
    db = get_db()

    if request.method == "POST":
        station_id = request.form.get("station_id")
        point_id = request.form.get("point_id")
        description = (request.form.get("description") or "").strip()

        if not station_id or not description:
            flash("Station and maintenance description are required.", "danger")
        else:
            try:
                sid = int(station_id)
                pid = int(point_id) if point_id else None

                cursor = db.cursor()
                cursor.execute("""
                    INSERT INTO maintenance (station_id, point_id, description, status)
                    VALUES (?, ?, ?, 'IN_PROGRESS')
                """, (sid, pid, description))

                if pid:
                    cursor.execute("UPDATE charging_points SET status = 'MAINTENANCE' WHERE id = ?", (pid,))

                db.commit()

                log_audit_event(
                    "MAINTENANCE_CREATED",
                    f"Maintenance logged by Admin {session['username']} for Station #{sid}, Point #{pid}: {description}",
                    severity="WARNING"
                )
                flash("Maintenance task scheduled. Charger marked under maintenance.", "success")
                return redirect(url_for("admin.maintenance"))
            except ValueError:
                flash("Invalid ID parameters.", "danger")

    tickets = db.execute("""
        SELECT m.*, s.name as station_name, cp.identifier as point_name
        FROM maintenance m
        JOIN stations s ON m.station_id = s.id
        LEFT JOIN charging_points cp ON m.point_id = cp.id
        ORDER BY m.created_at DESC
    """).fetchall()

    stations_list = db.execute("SELECT id, name FROM stations").fetchall()
    points_list = db.execute("SELECT id, identifier, station_id FROM charging_points").fetchall()

    return render_template(
        "admin/maintenance.html",
        tickets=tickets,
        stations=stations_list,
        points=points_list
    )

@admin_bp.route("/maintenance/<int:ticket_id>/resolve", methods=["POST"])
@admin_required
@csrf_protect
def resolve_maintenance(ticket_id):
    db = get_db()
    ticket = db.execute("SELECT * FROM maintenance WHERE id = ?", (ticket_id,)).fetchone()
    if not ticket:
        flash("Maintenance ticket not found.", "warning")
        return redirect(url_for("admin.maintenance"))

    now_iso = datetime.now(timezone.utc).isoformat()
    cursor = db.cursor()
    cursor.execute("""
        UPDATE maintenance 
        SET status = 'RESOLVED', resolved_at = ?
        WHERE id = ?
    """, (now_iso, ticket_id))

    if ticket["point_id"]:
        cursor.execute("UPDATE charging_points SET status = 'AVAILABLE' WHERE id = ?", (ticket["point_id"],))

    db.commit()

    log_audit_event(
        "MAINTENANCE_RESOLVED",
        f"Admin {session['username']} resolved maintenance ticket #{ticket_id}. Charger restored to AVAILABLE.",
        severity="INFO"
    )

    flash("Maintenance resolved. Charging point returned to operational status.", "success")
    return redirect(url_for("admin.maintenance"))

@admin_bp.route("/reservations")
@admin_required
def reservations():
    db = get_db()
    res_list = db.execute("""
        SELECT r.*, u.username, u.email, cp.identifier as point_name, s.name as station_name
        FROM reservations r
        JOIN users u ON r.user_id = u.id
        JOIN charging_points cp ON r.point_id = cp.id
        JOIN stations s ON cp.station_id = s.id
        ORDER BY r.created_at DESC
    """).fetchall()

    return render_template("admin/reservations.html", reservations=res_list)

@admin_bp.route("/sessions")
@admin_required
def sessions():
    db = get_db()
    sess_list = db.execute("""
        SELECT cs.*, u.username, cp.identifier as point_name, cp.tariff_per_kwh, s.name as station_name,
               p.amount as paid_amount, p.status as payment_status, p.transaction_ref
        FROM charging_sessions cs
        JOIN users u ON cs.user_id = u.id
        JOIN charging_points cp ON cs.point_id = cp.id
        JOIN stations s ON cp.station_id = s.id
        LEFT JOIN payments p ON p.session_id = cs.id
        ORDER BY cs.start_time DESC
    """).fetchall()

    return render_template("admin/sessions.html", sessions=sess_list)

@admin_bp.route("/logs")
@admin_bp.route("/audit-logs")
@admin_bp.route("/audit_logs")
@admin_required
def audit_logs():
    severity_filter = request.args.get("severity", "").strip()
    db = get_db()

    if severity_filter:
        logs_list = db.execute("""
            SELECT * FROM audit_logs 
            WHERE severity = ?
            ORDER BY timestamp DESC
        """, (severity_filter,)).fetchall()
    else:
        logs_list = db.execute("""
            SELECT * FROM audit_logs 
            ORDER BY timestamp DESC
        """).fetchall()

    return render_template("admin/audit_logs.html", logs=logs_list, current_severity=severity_filter)
