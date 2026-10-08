import time
import uuid
from datetime import datetime, timezone
from flask import Blueprint, render_template, request, jsonify, session, current_app
from app.database import get_db
from app.security import login_required, log_audit_event

vulns_bp = Blueprint("vulns_demo", __name__, url_prefix="/security-lab")

@vulns_bp.route("/")
def lab_home():
    """Security laboratory playground page displaying the 6 vulnerability demonstrations."""
    if not current_app.config.get("LAB_VULN_DEMO_ENABLED", False):
        return render_template("errors/403.html"), 403
    return render_template("security_lab/demo.html")

# ==============================================================================
# DEMONSTRATION 1: SQL INJECTION
# ==============================================================================
@vulns_bp.route("/demo/sqli", methods=["POST"])
def demo_sqli():
    """
    Comparison Endpoint: SQL Injection
    Payloads like: ' OR '1'='1' --
    """
    if not current_app.config.get("LAB_VULN_DEMO_ENABLED", False):
        return jsonify({"error": "Lab demo mode disabled."}), 403

    mode = request.json.get("mode", "vulnerable")
    query = request.json.get("input", "")
    db = get_db()
    cursor = db.cursor()

    if mode == "vulnerable":
        # VULNERABLE PATTERN: String concatenation into SQL query (for academic demonstration)
        raw_sql = f"SELECT id, name, location, status FROM stations WHERE name LIKE '%{query}%'"  # nosec B608
        try:
            results = [dict(row) for row in cursor.execute(raw_sql).fetchall()]
            return jsonify({
                "mode": "vulnerable",
                "executed_query": raw_sql,
                "count": len(results),
                "results": results,
                "analysis": "CRITICAL: The raw input was concatenated directly into SQL syntax. Payloads such as \"' OR '1'='1' --\" bypass filter logic completely."
            })
        except Exception as e:
            return jsonify({
                "mode": "vulnerable",
                "executed_query": raw_sql,
                "error": str(e),
                "analysis": "SQL Syntax Error induced by injected characters."
            }), 400
    else:
        # SECURE PATTERN: Parameterized Query
        safe_sql = "SELECT id, name, location, status FROM stations WHERE name LIKE ?"
        param = f"%{query}%"
        results = [dict(row) for row in cursor.execute(safe_sql, (param,)).fetchall()]
        return jsonify({
            "mode": "secure",
            "executed_query": safe_sql,
            "parameters": [param],
            "count": len(results),
            "results": results,
            "analysis": "SECURE: SQLite query engine treats the user input strictly as a literal data parameter, preventing command structure manipulation."
        })

# ==============================================================================
# DEMONSTRATION 2: PLAINTEXT PASSWORDS VS HASHING
# ==============================================================================
@vulns_bp.route("/demo/password-storage", methods=["POST"])
def demo_password():
    """
    Comparison Endpoint: Password Storage
    """
    if not current_app.config.get("LAB_VULN_DEMO_ENABLED", False):
        return jsonify({"error": "Lab demo mode disabled."}), 403

    mode = request.json.get("mode", "vulnerable")
    raw_password = request.json.get("password", "MyP@ssw0rd2026!")

    if mode == "vulnerable":
        stored_representation = raw_password
        return jsonify({
            "mode": "vulnerable",
            "plaintext_input": raw_password,
            "stored_in_database": stored_representation,
            "hash_algorithm": "NONE (Plaintext)",
            "analysis": "CRITICAL: If the database is compromised via SQLi or backup theft, all credentials are instantly exposed in clear text."
        })
    else:
        from werkzeug.security import generate_password_hash
        hashed_representation = generate_password_hash(raw_password)
        return jsonify({
            "mode": "secure",
            "plaintext_input": "[MASKED]",
            "stored_in_database": hashed_representation,
            "hash_algorithm": "Scrypt / PBKDF2 with Cryptographic Salt and High Cost Factor",
            "analysis": "SECURE: Passwords are irreversible one-way hashes with random salts. Precomputed rainbow tables and brute-force attacks are computationally infeasible."
        })

# ==============================================================================
# DEMONSTRATION 3: BROKEN AUTHORIZATION (ROLE CHECKING)
# ==============================================================================
@vulns_bp.route("/demo/authorization", methods=["POST"])
def demo_authz():
    """
    Comparison Endpoint: Role-based Authorization
    """
    if not current_app.config.get("LAB_VULN_DEMO_ENABLED", False):
        return jsonify({"error": "Lab demo mode disabled."}), 403

    mode = request.json.get("mode", "vulnerable")
    simulated_role = request.json.get("role", "USER")  # Normal user attempting admin action

    if mode == "vulnerable":
        # VULNERABLE: No role check, only checking if user is logged in (or not even that)
        return jsonify({
            "mode": "vulnerable",
            "user_role": simulated_role,
            "action_executed": "Station Power Limit Updated to 250 kW",
            "status": "ALLOWED (200 OK)",
            "analysis": "CRITICAL: Broken Object Level & Function Level Authorization. Standard user role performed privileged administrative modifications."
        })
    else:
        # SECURE: Strict role verification
        if simulated_role != "ADMIN":
            log_audit_event("AUTHORIZATION_FAILURE", f"Security Lab demo: Role {simulated_role} blocked from Admin action", severity="WARNING")
            return jsonify({
                "mode": "secure",
                "user_role": simulated_role,
                "status": "BLOCKED (403 Forbidden)",
                "error": "Access denied: Administrator role required.",
                "analysis": "SECURE: The request was intercepted by the @admin_required security decorator, logging an authorization failure audit record."
            }), 403
        return jsonify({
            "mode": "secure",
            "user_role": simulated_role,
            "status": "ALLOWED (200 OK)",
            "action_executed": "Station Power Limit Updated"
        })

# ==============================================================================
# DEMONSTRATION 4: CLIENT-CONTROLLED PAYMENT AMOUNT
# ==============================================================================
@vulns_bp.route("/demo/payment-tampering", methods=["POST"])
def demo_payment():
    """
    Comparison Endpoint: Payment Amount Verification
    """
    if not current_app.config.get("LAB_VULN_DEMO_ENABLED", False):
        return jsonify({"error": "Lab demo mode disabled."}), 403

    mode = request.json.get("mode", "vulnerable")
    actual_server_cost = 450.00  # Calculated by server: 25 kWh * 18/kWh
    client_supplied_amount = float(request.json.get("client_amount", 1.00))

    if mode == "vulnerable":
        # VULNERABLE: Trusting the amount sent in the JSON body from client
        recorded_payment = client_supplied_amount
        return jsonify({
            "mode": "vulnerable",
            "real_service_cost": actual_server_cost,
            "client_tampered_amount": client_supplied_amount,
            "charged_amount": recorded_payment,
            "status": "PAID",
            "analysis": "CRITICAL: Business logic flaw. Client manipulated the payment amount from ₹450.00 to ₹1.00 and the server accepted it without validation."
        })
    else:
        # SECURE: Server calculates amount authoritatively; client input ignored
        enforced_amount = actual_server_cost
        discrepancy = abs(client_supplied_amount - actual_server_cost) > 0.01
        return jsonify({
            "mode": "secure",
            "real_service_cost": actual_server_cost,
            "client_attempted_amount": client_supplied_amount,
            "charged_amount": enforced_amount,
            "tampering_detected": discrepancy,
            "status": "PAID with Authoritative Server Price",
            "analysis": "SECURE: The server strictly calculated the payment value based on immutable database telemetry (kWh * tariff). The client's submitted amount was disregarded."
        })

# ==============================================================================
# DEMONSTRATION 5: CONCURRENT RESERVATION RACE CONDITION
# ==============================================================================
@vulns_bp.route("/demo/race-condition", methods=["POST"])
def demo_race():
    """
    Comparison Endpoint: Concurrent Slot Reservation
    """
    if not current_app.config.get("LAB_VULN_DEMO_ENABLED", False):
        return jsonify({"error": "Lab demo mode disabled."}), 403

    mode = request.json.get("mode", "vulnerable")
    point_id = int(request.json.get("point_id", 1))

    if mode == "vulnerable":
        # VULNERABLE: Time-of-check to time-of-use (TOCTOU) gap
        # Simulation of 2 concurrent threads checking availability before committing
        return jsonify({
            "mode": "vulnerable",
            "thread_1_check": "Point status is AVAILABLE",
            "thread_2_check": "Point status is AVAILABLE (Read before Thread 1 committed)",
            "thread_1_result": "Reservation #101 CREATED for User A",
            "thread_2_result": "Reservation #102 CREATED for User B (DOUBLE BOOKING)",
            "status": "RACE CONDITION EXPLOITED",
            "analysis": "CRITICAL: Non-atomic check and update creates a window where two users can reserve the exact same charging connector simultaneously."
        })
    else:
        # SECURE: Atomic test-and-set query
        # UPDATE charging_points SET status = 'RESERVED' WHERE id = ? AND status = 'AVAILABLE'
        return jsonify({
            "mode": "secure",
            "query_atomic": "UPDATE charging_points SET status = 'RESERVED' WHERE id = :id AND status = 'AVAILABLE'",
            "thread_1_result": "Rowcount = 1 -> SUCCESS: Reserved for User A",
            "thread_2_result": "Rowcount = 0 -> CONFLICT (409): Rejected. Prevented collision.",
            "status": "ATOMIC ISOLATION ENFORCED",
            "analysis": "SECURE: Atomic database update guarantees that only the single thread that wins the race modifies the row. The second request is safely rejected with conflict notification."
        })

# ==============================================================================
# DEMONSTRATION 6: IDOR (INSECURE DIRECT OBJECT REFERENCE)
# ==============================================================================
@vulns_bp.route("/demo/idor", methods=["POST"])
def demo_idor():
    """
    Comparison Endpoint: Insecure Direct Object Reference
    """
    if not current_app.config.get("LAB_VULN_DEMO_ENABLED", False):
        return jsonify({"error": "Lab demo mode disabled."}), 403

    mode = request.json.get("mode", "vulnerable")
    target_session_id = int(request.json.get("session_id", 42))
    simulated_user_id = 99  # Attacker user ID
    victim_user_id = 5     # Real owner of session 42

    if mode == "vulnerable":
        # VULNERABLE: Query only checks session ID: "SELECT * FROM sessions WHERE id = :id"
        return jsonify({
            "mode": "vulnerable",
            "attacker_user_id": simulated_user_id,
            "target_session_id": target_session_id,
            "query_executed": f"SELECT * FROM charging_sessions WHERE id = {target_session_id}",  # nosec B608
            "victim_data_exposed": {
                "owner_user_id": victim_user_id,
                "vehicle": "Tesla Model 3 / Nexon EV",
                "energy_kwh": 38.5,
                "amount": 770.00,
                "status": "COMPLETED"
            },
            "status": "UNAUTHORIZED ACCESS GRANTED",
            "analysis": "CRITICAL: The application blindly retrieved data by object ID without asserting ownership against the authenticated user session."
        })
    else:
        # SECURE: Query strictly checks both ID and user_id: "WHERE id = ? AND user_id = ?"
        return jsonify({
            "mode": "secure",
            "attacker_user_id": simulated_user_id,
            "target_session_id": target_session_id,
            "query_executed": "SELECT * FROM charging_sessions WHERE id = ? AND user_id = ?",
            "query_parameters": [target_session_id, simulated_user_id],
            "result": "No matching record found for this user",
            "status": "ACCESS BLOCKED (403/404)",
            "analysis": "SECURE: Query-level scoping guarantees horizontal authorization. A user can strictly access objects that belong directly to their account ID."
        })
