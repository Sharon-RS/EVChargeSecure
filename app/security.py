import re
import secrets
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import session, request, redirect, url_for, flash, abort, jsonify, g, current_app
from app.database import get_db

USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_-]{3,30}$")
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
PASSWORD_REGEX = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&_\-#])[A-Za-z\d@$!%*?&_\-#]{8,64}$")

SENSITIVE_PATTERNS = ["password", "token", "secret", "cvv", "card_number", "auth_key"]

def sanitize_audit_text(text: str) -> str:
    """Mask any potentially sensitive values in audit description."""
    if not text:
        return ""
    sanitized = text
    for word in SENSITIVE_PATTERNS:
        sanitized = re.sub(rf"({word}\s*[:=]\s*)(\S+)", r"\1[REDACTED]", sanitized, flags=re.IGNORECASE)
    return sanitized

def log_audit_event(event_type: str, description: str, severity: str = "INFO", 
                    user_id: int = None, username: str = None, ip_address: str = None):
    """
    Record a security or operational event to the audit_logs table.
    Ensures no passwords or secrets are ever recorded.
    """
    try:
        db = get_db()
        actual_user_id = user_id or session.get("user_id")
        actual_username = username or session.get("username")
        actual_ip = ip_address or request.remote_addr or "127.0.0.1"

        safe_desc = sanitize_audit_text(description)

        db.execute("""
            INSERT INTO audit_logs (user_id, username, event_type, ip_address, description, severity)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (actual_user_id, actual_username, event_type, actual_ip, safe_desc, severity))
        db.commit()
    except Exception as exc:
        # Fallback to application logger if DB write fails; do not crash request
        if current_app:
            current_app.logger.error(f"Audit log write failure: {exc}")

def generate_csrf_token() -> str:
    """Generate or return existing session CSRF token."""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]

def verify_csrf_token() -> bool:
    """Verify CSRF token from either request form or custom X-CSRFToken header."""
    session_token = session.get("_csrf_token")
    if not session_token:
        return False
    
    token = request.form.get("csrf_token") or request.headers.get("X-CSRFToken")
    if not token and request.is_json:
        token = request.get_json(silent=True, force=False)
        if isinstance(token, dict):
            token = token.get("csrf_token")
        else:
            token = None

    if not token:
        return False

    return secrets.compare_digest(str(token), str(session_token))

def csrf_protect(f):
    """Decorator to enforce CSRF validation on mutating HTTP requests."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ["POST", "PUT", "DELETE", "PATCH"]:
            if not verify_csrf_token():
                log_audit_event(
                    "CSRF_VIOLATION",
                    f"Invalid or missing CSRF token on endpoint {request.path}",
                    severity="SECURITY_ALERT"
                )
                if request.is_json:
                    return jsonify({"error": "CSRF validation failed: Invalid or missing token."}), 403
                flash("Security verification failed (Invalid CSRF token). Please try again.", "danger")
                return redirect(request.referrer or url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated_function

def login_required(f):
    """Enforce that the requesting client is authenticated."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("user_id"):
            if request.is_json:
                return jsonify({"error": "Authentication required"}), 401
            flash("Please sign in to access this page.", "warning")
            return redirect(url_for("auth.login", next=request.path))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Enforce that the authenticated user possesses the ADMIN role."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("user_id"):
            if request.is_json:
                return jsonify({"error": "Authentication required"}), 401
            flash("Please sign in as administrator to proceed.", "warning")
            return redirect(url_for("auth.login", next=request.path))

        if session.get("role") != "ADMIN":
            log_audit_event(
                "AUTHORIZATION_FAILURE",
                f"Unauthorized attempt to access admin resource: {request.path}",
                severity="WARNING"
            )
            if request.is_json:
                return jsonify({"error": "Forbidden: Administrator role required"}), 403
            flash("Access denied: Administrator privileges required.", "danger")
            return redirect(url_for("user.dashboard"))

        return f(*args, **kwargs)
    return decorated_function

def validate_username(username: str) -> tuple[bool, str]:
    """Validate username format and length."""
    if not username:
        return False, "Username is required."
    username = username.strip()
    if not USERNAME_REGEX.match(username):
        return False, "Username must be 3-30 characters and contain only letters, numbers, hyphens, and underscores."
    return True, ""

def validate_email(email: str) -> tuple[bool, str]:
    """Validate email format."""
    if not email:
        return False, "Email address is required."
    email = email.strip()
    if not EMAIL_REGEX.match(email):
        return False, "Please enter a valid email address."
    return True, ""

def validate_password_strength(password: str) -> tuple[bool, str]:
    """Enforce NIST-aligned strong password policy."""
    if not password:
        return False, "Password is required."
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if len(password) > 64:
        return False, "Password must not exceed 64 characters."
    if not PASSWORD_REGEX.match(password):
        return False, "Password must contain at least 1 uppercase letter, 1 lowercase letter, 1 number, and 1 special symbol (@$!%*?&_#-)."
    return True, ""

def check_account_lockout(user_row) -> tuple[bool, str]:
    """Check if the user account is temporarily locked due to repeated failed logins."""
    locked_until_str = user_row["locked_until"]
    if not locked_until_str:
        return False, ""

    try:
        locked_until = datetime.fromisoformat(locked_until_str)
        if datetime.now(timezone.utc) < locked_until:
            remaining_mins = max(1, int((locked_until - datetime.now(timezone.utc)).total_seconds() / 60))
            return True, f"Account is temporarily locked due to excessive failed attempts. Try again in {remaining_mins} minute(s)."
    except (ValueError, TypeError) as exc:
        if current_app:
            current_app.logger.debug(f"Lockout timestamp parse error: {exc}")

    return False, ""

def register_login_failure(db, user_row, ip_address: str):
    """Increment failed login attempts and trigger lockout if threshold is exceeded."""
    new_attempts = (user_row["failed_login_attempts"] or 0) + 1
    max_attempts = current_app.config.get("MAX_FAILED_LOGIN_ATTEMPTS", 5)
    lockout_minutes = current_app.config.get("LOCKOUT_DURATION_MINUTES", 15)

    if new_attempts >= max_attempts:
        lock_until = datetime.now(timezone.utc) + timedelta(minutes=lockout_minutes)
        db.execute("""
            UPDATE users 
            SET failed_login_attempts = ?, locked_until = ?
            WHERE id = ?
        """, (new_attempts, lock_until.isoformat(), user_row["id"]))
        db.commit()

        log_audit_event(
            "ACCOUNT_LOCKED",
            f"Account locked for {user_row['username']} after {new_attempts} consecutive failed attempts from IP {ip_address}",
            severity="SECURITY_ALERT",
            user_id=user_row["id"],
            username=user_row["username"],
            ip_address=ip_address
        )
    else:
        db.execute("""
            UPDATE users 
            SET failed_login_attempts = ?
            WHERE id = ?
        """, (new_attempts, user_row["id"]))
        db.commit()

        log_audit_event(
            "LOGIN_FAILED",
            f"Failed login attempt ({new_attempts}/{max_attempts}) for user {user_row['username']}",
            severity="WARNING",
            user_id=user_row["id"],
            username=user_row["username"],
            ip_address=ip_address
        )

def reset_login_failures(db, user_id: int):
    """Reset failed attempts count upon successful authentication."""
    db.execute("""
        UPDATE users 
        SET failed_login_attempts = 0, locked_until = NULL
        WHERE id = ?
    """, (user_id,))
    db.commit()
