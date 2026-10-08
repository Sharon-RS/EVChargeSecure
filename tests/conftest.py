import os
import sys
import re
import pytest
from pathlib import Path

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app
from app.config import TestingConfig
from app.database import init_db, seed_demo_data, get_db

@pytest.fixture
def app():
    """Create and configure a testing Flask application."""
    test_db_path = str(Path.home() / ".evcharge" / "test_evcharge.db")
    TestingConfig.DB_PATH = test_db_path
    
    # Remove existing test db if present
    if os.path.exists(test_db_path):
        try:
            os.remove(test_db_path)
        except OSError:
            pass

    app = create_app(TestingConfig)

    with app.app_context():
        init_db(app)
        seed_demo_data(get_db())

    yield app

    # Cleanup after test suite
    if os.path.exists(test_db_path):
        try:
            os.remove(test_db_path)
        except OSError:
            pass

@pytest.fixture
def client(app):
    """Test HTTP client."""
    return app.test_client()

def extract_csrf_token(response):
    """Helper to extract CSRF token from HTML response."""
    html = response.get_data(as_text=True)
    # Search for meta tag or hidden input
    meta_match = re.search(r'<meta name="csrf-token" content="([a-f0-9]+)"', html)
    if meta_match:
        return meta_match.group(1)
    input_match = re.search(r'name="csrf_token" value="([a-f0-9]+)"', html)
    if input_match:
        return input_match.group(1)
    return ""

@pytest.fixture
def user_client(client):
    """Authenticated client for regular user (user1)."""
    # Get login page for CSRF token
    res = client.get("/auth/login")
    token = extract_csrf_token(res)
    client.post("/auth/login", data={
        "username": "user1",
        "password": "User1@Secure2026!",
        "csrf_token": token
    }, follow_redirects=True)
    return client

@pytest.fixture
def admin_client(client):
    """Authenticated client for administrator (admin)."""
    res = client.get("/auth/login")
    token = extract_csrf_token(res)
    client.post("/auth/login", data={
        "username": "admin",
        "password": "Admin@Secure2026!",
        "csrf_token": token
    }, follow_redirects=True)
    return client
