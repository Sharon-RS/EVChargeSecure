from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from app.database import get_db
from app.security import (
    validate_username, validate_email, validate_password_strength,
    check_account_lockout, register_login_failure, reset_login_failures,
    log_audit_event, csrf_protect, generate_csrf_token
)

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

@auth_bp.route("/register", methods=["GET", "POST"])
@csrf_protect
def register():
    if session.get("user_id"):
        return redirect(url_for("user.dashboard"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        confirm_password = request.form.get("confirm_password") or ""

        # Validate inputs
        u_valid, u_err = validate_username(username)
        if not u_valid:
            flash(u_err, "danger")
            return render_template("auth/register.html", username=username, email=email)

        e_valid, e_err = validate_email(email)
        if not e_valid:
            flash(e_err, "danger")
            return render_template("auth/register.html", username=username, email=email)

        p_valid, p_err = validate_password_strength(password)
        if not p_valid:
            flash(p_err, "danger")
            return render_template("auth/register.html", username=username, email=email)

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("auth/register.html", username=username, email=email)

        db = get_db()
        cursor = db.cursor()

        # Parameterized query to check existing credentials
        cursor.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email))
        if cursor.fetchone():
            flash("Username or email is already registered. Please sign in or use another username.", "danger")
            return render_template("auth/register.html", username=username, email=email)

        # Hash password securely using Werkzeug's default modern scrypt/pbkdf2
        password_hash = generate_password_hash(password)

        cursor.execute("""
            INSERT INTO users (username, email, password_hash, role)
            VALUES (?, ?, ?, 'USER')
        """, (username, email, password_hash))
        db.commit()

        user_id = cursor.lastrowid

        log_audit_event(
            "USER_REGISTERED",
            f"New user registered: {username} ({email})",
            severity="INFO",
            user_id=user_id,
            username=username
        )

        # Regenerate session on registration to prevent session fixation
        session.clear()
        session["user_id"] = user_id
        session["username"] = username
        session["role"] = "USER"
        generate_csrf_token()

        flash(f"Welcome, {username}! Your account has been securely created.", "success")
        return redirect(url_for("user.dashboard"))

    return render_template("auth/register.html")

@auth_bp.route("/login", methods=["GET", "POST"])
@csrf_protect
def login():
    if session.get("user_id"):
        if session.get("role") == "ADMIN":
            return redirect(url_for("admin.dashboard"))
        return redirect(url_for("user.dashboard"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        next_url = request.args.get("next") or request.form.get("next")

        if not username or not password:
            flash("Please enter both username and password.", "danger")
            return render_template("auth/login.html", username=username)

        db = get_db()
        cursor = db.cursor()

        # Parameterized SQL query
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if not user:
            # Generic error to prevent username enumeration while logging attempt
            log_audit_event(
                "LOGIN_FAILED",
                f"Failed login attempt for non-existent user: {username}",
                severity="WARNING",
                username=username
            )
            flash("Invalid username or password.", "danger")
            return render_template("auth/login.html", username=username)

        # Check account lockout
        is_locked, lock_message = check_account_lockout(user)
        if is_locked:
            flash(lock_message, "danger")
            return render_template("auth/login.html", username=username)

        # Verify password hash
        if not check_password_hash(user["password_hash"], password):
            register_login_failure(db, user, request.remote_addr or "127.0.0.1")
            flash("Invalid username or password.", "danger")
            return render_template("auth/login.html", username=username)

        # Authentication successful: reset failure counts
        reset_login_failures(db, user["id"])

        # Prevent Session Fixation: clear previous session and assign fresh ID
        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]
        generate_csrf_token()

        log_audit_event(
            "LOGIN_SUCCESS",
            f"User {user['username']} logged in successfully with role {user['role']}",
            severity="INFO",
            user_id=user["id"],
            username=user["username"]
        )

        flash(f"Welcome back, {user['username']}!", "success")

        # Validate redirect target to prevent open redirect vulnerabilities
        if next_url and next_url.startswith("/") and not next_url.startswith("//"):
            return redirect(next_url)

        if user["role"] == "ADMIN":
            return redirect(url_for("admin.dashboard"))
        return redirect(url_for("user.dashboard"))

    return render_template("auth/login.html")

@auth_bp.route("/logout", methods=["GET", "POST"])
def logout():
    username = session.get("username")
    user_id = session.get("user_id")

    if user_id:
        log_audit_event(
            "LOGOUT",
            f"User {username} logged out.",
            severity="INFO",
            user_id=user_id,
            username=username
        )

    session.clear()
    flash("You have been signed out securely.", "info")
    return redirect(url_for("auth.login"))
