#!/usr/bin/env python3
"""
EVChargeSecure - Application Runner
Secure EV Charging Station Management System
"""
import os
import sys
from pathlib import Path

# Add root directory to path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app import create_app
from app.config import Config

app = create_app(Config)

if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0").lower() in ("1", "true")
    
    print("=" * 60)
    print("  EVChargeSecure - Secure EV Charging Station Platform")
    print(f"  Listening on http://{host}:{port}")
    print("  Zero-Trust Session & Header Hardening: Active")
    print("=" * 60)
    
    app.run(host=host, port=port, debug=debug)
