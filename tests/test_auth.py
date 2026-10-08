import pytest
from tests.conftest import extract_csrf_token
from app.database import get_db
from werkzeug.security import check_password_hash

def test_user_registration_success(client, app):
    """Test user registration with compliant password policy."""
    res = client.get("/auth/register")
    token = extract_csrf_token(res)

    post_res = client.post("/auth/register", data={
        "username": "newdriver",
        "email": "driver@example.com",
        "password": "SecurePassword123!",
        "confirm_password": "SecurePassword123!",
        "csrf_token": token
    }, follow_redirects=True)

    assert post_res.status_code == 200
    assert b"Welcome, newdriver!" in post_res.data

    with app.app_context():
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = 'newdriver'").fetchone()
        assert user is not None
        assert user["email"] == "driver@example.com"
        # Confirm password is NOT plaintext
        assert user["password_hash"] != "SecurePassword123!"
        assert check_password_hash(user["password_hash"], "SecurePassword123!")

def test_user_registration_weak_password_rejected(client):
    """Test registration rejects weak passwords (length < 8 or missing symbols)."""
    res = client.get("/auth/register")
    token = extract_csrf_token(res)

    # Missing special character and number
    post_res = client.post("/auth/register", data={
        "username": "weakuser",
        "email": "weak@example.com",
        "password": "weakpassword",
        "confirm_password": "weakpassword",
        "csrf_token": token
    }, follow_redirects=True)

    assert b"Password must contain at least 1 uppercase" in post_res.data or b"Password must be at least 8 characters" in post_res.data

def test_login_success(client):
    """Test login with valid pre-seeded credentials."""
    res = client.get("/auth/login")
    token = extract_csrf_token(res)

    login_res = client.post("/auth/login", data={
        "username": "user1",
        "password": "User1@Secure2026!",
        "csrf_token": token
    }, follow_redirects=True)

    assert login_res.status_code == 200
    assert b"Welcome back, user1!" in login_res.data
    assert b"Driver Fleet Portal" in login_res.data

def test_login_invalid_password(client):
    """Test login with wrong password produces generic error."""
    res = client.get("/auth/login")
    token = extract_csrf_token(res)

    login_res = client.post("/auth/login", data={
        "username": "user1",
        "password": "WrongPassword999!",
        "csrf_token": token
    }, follow_redirects=True)

    assert login_res.status_code == 200
    assert b"Invalid username or password" in login_res.data

def test_account_lockout_after_multiple_failures(app):
    """Test account lockout activates after 5 consecutive failed login attempts."""
    fresh_client = app.test_client()
    for i in range(5):
        res = fresh_client.get("/auth/login")
        token = extract_csrf_token(res)
        fresh_client.post("/auth/login", data={
            "username": "sharon",
            "password": "WrongPassword!",
            "csrf_token": token
        }, follow_redirects=True)

    # 6th attempt should be blocked due to account lockout
    res = fresh_client.get("/auth/login")
    token = extract_csrf_token(res)
    locked_res = fresh_client.post("/auth/login", data={
        "username": "sharon",
        "password": "Sharon@Secure2026!",  # Even with correct password, account is locked
        "csrf_token": token
    }, follow_redirects=True)

    assert b"Account is temporarily locked" in locked_res.data

def test_logout(user_client):
    """Test logout clears user session."""
    logout_res = user_client.post("/auth/logout", follow_redirects=True)
    assert logout_res.status_code == 200
    assert b"You have been signed out securely" in logout_res.data

    # Attempting to access dashboard should now redirect to login
    dash_res = user_client.get("/user/dashboard", follow_redirects=False)
    assert dash_res.status_code in [302, 401]
