import os
import secrets
from datetime import timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

def get_default_db_path(filename="evcharge_secure.db") -> str:
    """
    Resolve a writable database path.
    Prefers environment variable DATABASE_PATH.
    Falls back to instance/ in the project root if writable,
    or ~/.evcharge/ directory (compatible with Windows Controlled Folder Access).
    """
    env_path = os.environ.get("DATABASE_PATH")
    if env_path:
        return env_path

    # Try local instance directory
    local_dir = BASE_DIR / "instance"
    try:
        os.makedirs(local_dir, exist_ok=True)
        test_probe = local_dir / ".probe"
        with open(test_probe, "w") as f:
            f.write("1")
        test_probe.unlink(missing_ok=True)
        return str(local_dir / filename)
    except (OSError, IOError):
        # Fallback to user home folder
        user_dir = Path.home() / ".evcharge"
        os.makedirs(user_dir, exist_ok=True)
        return str(user_dir / filename)

class Config:
    """Application configuration with secure defaults."""
    # Secret key from environment or cryptographically generated per-boot fallback
    SECRET_KEY = os.environ.get("EV_SECRET_KEY") or os.environ.get("SECRET_KEY") or secrets.token_hex(32)  # nosec B105

    # Database configuration
    DB_PATH = get_default_db_path("evcharge_secure.db")

    # Session & Cookie Security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("FLASK_ENV") == "production"
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=60)

    # Security Controls
    MAX_FAILED_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION_MINUTES = 15

    # Educational Laboratory Demonstration Module
    LAB_VULN_DEMO_ENABLED = os.environ.get("LAB_VULN_DEMO_ENABLED", "true").lower() in ("true", "1")

class TestingConfig(Config):
    """Testing configuration with isolated test database."""
    TESTING = True
    SECRET_KEY = os.environ.get("TEST_SECRET_KEY", "test-isolated-key-for-pytest-execution")  # nosec B105
    DB_PATH = get_default_db_path("test_evcharge.db")
    LAB_VULN_DEMO_ENABLED = True
