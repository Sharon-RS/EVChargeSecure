#!/usr/bin/env python3
"""
EVChargeSecure - Database Initialization and Seeding Script
Populates demo stations, charging points, initial accounts, and baseline security logs.
"""
import os
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app import create_app
from app.database import get_db, init_db, seed_demo_data

def run_seed():
    app = create_app()
    with app.app_context():
        db = get_db()
        print("[*] Initializing EVChargeSecure SQLite database schema...")
        init_db(app)
        print("[*] Populating seed stations and demo credentials...")
        seed_demo_data(db)
        print("[+] Database seeding completed successfully!")
        print("\nDefault Accounts for Lab Demonstration:")
        print("  1. Admin Account:  Username: admin   | Password: Admin@Secure2026!")
        print("  2. Driver Account: Username: user1   | Password: User1@Secure2026!")
        print("  3. Driver Account: Username: sharon  | Password: Sharon@Secure2026!")

if __name__ == "__main__":
    run_seed()
