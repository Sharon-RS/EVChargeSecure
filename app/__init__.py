import os
from flask import Flask, render_template, redirect, url_for, session, jsonify, request
from app.config import Config
from app.database import close_db, init_db, seed_demo_data, get_db
from app.security import generate_csrf_token

def create_app(config_class=Config):
    """Application factory for EVChargeSecure."""
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config_class)

    # Ensure instance directory exists
    try:
        os.makedirs(app.instance_path, exist_ok=True)
    except OSError:
        pass

    # Database teardown hook
    app.teardown_appcontext(close_db)

    # Context processors for templates
    @app.context_processor
    def inject_globals():
        return {
            "csrf_token": generate_csrf_token,
            "current_user": {
                "id": session.get("user_id"),
                "username": session.get("username"),
                "role": session.get("role")
            }
        }

    # Jinja template filter for currency
    @app.template_filter("format_inr")
    def format_inr(value):
        try:
            return f"₹{float(value):,.2f}"
        except (ValueError, TypeError):
            return f"₹0.00"

    @app.template_filter("format_timestamp")
    def format_timestamp(value):
        if not value:
            return ""
        if hasattr(value, "strftime"):
            return value.strftime("%Y-%m-%d %H:%M:%S")
        return str(value)[:19].replace("T", " ")

    # Security HTTP Response Headers
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Robust Content-Security-Policy allowing standard Google Fonts and local assets
        csp = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
            "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
            "script-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "frame-ancestors 'none';"
        )
        response.headers["Content-Security-Policy"] = csp
        return response

    # Register Blueprints
    from app.auth import auth_bp
    from app.user_routes import user_bp
    from app.admin_routes import admin_bp
    from app.vulns_demo import vulns_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(vulns_bp)

    # Root route redirection
    @app.route("/")
    def index():
        if session.get("user_id"):
            if session.get("role") == "ADMIN":
                return redirect(url_for("admin.dashboard"))
            return redirect(url_for("user.dashboard"))
        return redirect(url_for("auth.login"))

    # Secure Error Handlers (Prevents stack trace leaks to users)
    @app.errorhandler(400)
    def bad_request(error):
        if request.is_json:
            return jsonify({"error": "Bad Request: Malformed or invalid input."}), 400
        return render_template("errors/400.html"), 400

    @app.errorhandler(403)
    def forbidden(error):
        if request.is_json:
            return jsonify({"error": "Forbidden: You lack necessary permissions."}), 403
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def page_not_found(error):
        if request.is_json:
            return jsonify({"error": "Resource not found."}), 404
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error(f"Internal Server Error: {error}")
        if request.is_json:
            return jsonify({"error": "Internal server error occurred. Please contact support."}), 500
        return render_template("errors/500.html"), 500

    # Auto-initialize database and seed demo data on first boot
    with app.app_context():
        init_db()
        seed_demo_data(get_db())

    return app
