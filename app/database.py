import sqlite3
import os
from pathlib import Path
from flask import g, current_app
from werkzeug.security import generate_password_hash

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'USER',
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TEXT DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS stations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    location TEXT NOT NULL,
    address TEXT NOT NULL,
    total_points INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS charging_points (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    station_id INTEGER NOT NULL,
    identifier TEXT NOT NULL,
    connector_type TEXT NOT NULL,
    max_power_kw REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'AVAILABLE',
    tariff_per_kwh REAL NOT NULL,
    FOREIGN KEY (station_id) REFERENCES stations (id) ON DELETE CASCADE,
    UNIQUE(station_id, identifier)
);

CREATE TABLE IF NOT EXISTS reservations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    point_id INTEGER NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (point_id) REFERENCES charging_points (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS charging_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    point_id INTEGER NOT NULL,
    reservation_id INTEGER,
    start_time TEXT NOT NULL,
    end_time TEXT,
    energy_kwh REAL DEFAULT 0.0,
    total_cost REAL DEFAULT 0.0,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (point_id) REFERENCES charging_points (id) ON DELETE CASCADE,
    FOREIGN KEY (reservation_id) REFERENCES reservations (id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL UNIQUE,
    user_id INTEGER NOT NULL,
    amount REAL NOT NULL,
    currency TEXT NOT NULL DEFAULT 'INR',
    payment_method TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PAID',
    transaction_ref TEXT UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES charging_sessions (id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS maintenance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    station_id INTEGER NOT NULL,
    point_id INTEGER,
    description TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'SCHEDULED',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TEXT,
    FOREIGN KEY (station_id) REFERENCES stations (id) ON DELETE CASCADE,
    FOREIGN KEY (point_id) REFERENCES charging_points (id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    username TEXT,
    event_type TEXT NOT NULL,
    ip_address TEXT,
    description TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'INFO',
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_reservations_point_status ON reservations(point_id, status);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON charging_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_points_station ON charging_points(station_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
"""

def get_db():
    """Retrieve SQLite database connection for current request context."""
    if 'db' not in g:
        db_path = current_app.config['DB_PATH']
        # Ensure parent directory exists
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(
            db_path,
            timeout=30.0
        )
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON;")
    return g.db

def close_db(e=None):
    """Close the database connection at the end of the request."""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db(app=None):
    """Initialize database schema."""
    if app:
        with app.app_context():
            db = get_db()
            db.executescript(SCHEMA_SQL)
            db.commit()
    else:
        db = get_db()
        db.executescript(SCHEMA_SQL)
        db.commit()

def seed_demo_data(db):
    """Populate initial demo stations, charging points, and default accounts."""
    cursor = db.cursor()

    # Check if stations are already seeded
    cursor.execute("SELECT COUNT(*) as count FROM stations")
    if cursor.fetchone()['count'] > 0:
        return

    # Seed Admin User and Standard User
    admin_hash = generate_password_hash("Admin@Secure2026!")
    user_hash = generate_password_hash("User1@Secure2026!")
    sharon_hash = generate_password_hash("Sharon@Secure2026!")

    cursor.execute("""
        INSERT OR IGNORE INTO users (username, email, password_hash, role)
        VALUES 
        ('admin', 'admin@evchargesecure.local', ?, 'ADMIN'),
        ('user1', 'user1@evchargesecure.local', ?, 'USER'),
        ('sharon', 'sharon@evchargesecure.local', ?, 'USER')
    """, (admin_hash, user_hash, sharon_hash))

    # Seed Stations
    stations_data = [
        ("Chennai Central EV Hub", "Central Station Forecourt, Chennai", "Park Town, Chennai, Tamil Nadu 600003", 4, "ACTIVE"),
        ("Anna Nagar EV Station", "2nd Avenue, Near Tower Park, Chennai", "Anna Nagar West, Chennai, Tamil Nadu 600040", 4, "ACTIVE"),
        ("Guindy GreenCharge", "Industrial Estate Road, Guindy, Chennai", "Guindy, Chennai, Tamil Nadu 600032", 3, "ACTIVE"),
        ("OMR FastCharge", "IT Corridor, Sholinganallur, Chennai", "Rajiv Gandhi Salai, Chennai, Tamil Nadu 600119", 4, "ACTIVE"),
    ]

    for name, loc, addr, total_pts, status in stations_data:
        cursor.execute("""
            INSERT INTO stations (name, location, address, total_points, status)
            VALUES (?, ?, ?, ?, ?)
        """, (name, loc, addr, total_pts, status))
        station_id = cursor.lastrowid

        # Seed Charging Points for each station
        # Connectors: CCS2, Type 2, CHAdeMO
        points_data = [
            (station_id, "CP-01", "CCS2 (DC Fast)", 60.0, "AVAILABLE", 18.50),
            (station_id, "CP-02", "CCS2 (DC Fast)", 120.0, "AVAILABLE", 22.00),
            (station_id, "CP-03", "Type 2 (AC)", 22.0, "AVAILABLE", 14.00),
        ]
        if total_pts >= 4:
            points_data.append((station_id, "CP-04", "CHAdeMO", 50.0, "AVAILABLE", 17.50))

        for sid, identifier, conn_type, max_pwr, p_status, tariff in points_data:
            cursor.execute("""
                INSERT INTO charging_points (station_id, identifier, connector_type, max_power_kw, status, tariff_per_kwh)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (sid, identifier, conn_type, max_pwr, p_status, tariff))

    # Set a few charging points to illustrative initial states for demo
    cursor.execute("UPDATE charging_points SET status = 'CHARGING' WHERE id = 2")
    cursor.execute("UPDATE charging_points SET status = 'MAINTENANCE' WHERE id = 7")

    # Add demo maintenance ticket
    cursor.execute("""
        INSERT INTO maintenance (station_id, point_id, description, status)
        VALUES (2, 7, 'Connector latch inspection and periodic calibration', 'IN_PROGRESS')
    """)

    # Add demo audit log entry
    cursor.execute("""
        INSERT INTO audit_logs (user_id, username, event_type, ip_address, description, severity)
        VALUES (1, 'system', 'SYSTEM_INIT', '127.0.0.1', 'EVChargeSecure database initialized with baseline security policies and demo stations.', 'INFO')
    """)

    db.commit()
