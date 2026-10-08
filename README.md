# EVChargeSecure ⚡
### Secure EV Charging Station Management System
*Secure Software Engineering End-Semester Laboratory Project*

![Python 3.12](https://img.shields.io/badge/Python-3.12-blue.svg)
![Flask](https://img.shields.io/badge/Flask-3.1-black.svg)
![Tests](https://img.shields.io/badge/Tests-27%20Passed-brightgreen.svg)
![Bandit SAST](https://img.shields.io/badge/Bandit-0%20Issues-success.svg)
![pip-audit](https://img.shields.io/badge/pip--audit-0%20Vulnerabilities-success.svg)
![Docker](https://img.shields.io/badge/Docker-Hardened%20Non--Root-blue.svg)
![Kubernetes](https://img.shields.io/badge/Kubernetes-Manifests%20Ready-326CE5.svg)

---

## 📖 Overview

**EVChargeSecure** is a functional, visually modern, and hardened EV charging station management platform built for the **Secure Software Engineering** end-semester laboratory evaluation.

The system addresses both daily operations for EV drivers (station locating, atomic slot booking, live simulated high-voltage charging, and authoritative server-side billing) and fleet administration (power limit calibration, station/charger provisioning, maintenance scheduling, and security audit log analysis).

In addition to secure production controls, the platform incorporates a dedicated **Security Laboratory Demonstration Module** (`/security-lab`) comparing **6 critical vulnerabilities** side-by-side with their hardened defenses.

---

## 🚀 Key Features

### Driver Experience (USER Role)
- **Station Directory:** Browse and filter charging hubs across Chennai (Chennai Central, Anna Nagar, Guindy, OMR).
- **Live Terminal Telemetry:** Real-time visibility into connector types (CCS2 DC Fast, Type 2 AC, CHAdeMO) and availability.
- **Atomic Slot Reservation:** Guaranteed single-slot booking protected against race conditions and hoarding.
- **Active Charging Session:** Simulated live charging meter displaying accrued kWh, real-time power rate, and cost.
- **Authoritative Server Payment:** Zero client trust; billing calculations are strictly calculated on the backend.
- **Charging & Payment History:** Scoped strictly to the authenticated driver with cryptographic transaction receipts.

### Fleet Management (ADMIN Role)
- **Fleet Command Center:** Overview of system load, total energy dispensed, and revenue metrics.
- **Station Management:** Deploy, update, and manage charging hubs.
- **Charging Point & Power Limit Control:** Dynamically adjust terminal power ratings (kW) and energy tariffs.
- **Maintenance Operations:** Schedule downtime maintenance and restore repaired chargers to operational status.
- **Fleet Audit Trail:** Searchable, filterable security and operations audit log with automatic secret sanitization.

### Security Demonstrations (Laboratory Evaluation)
Side-by-side code comparisons and interactive live test harnesses for:
1. **SQL Injection (CWE-89)**
2. **Plaintext Password Storage (CWE-256/312)**
3. **Broken Authorization & Missing RBAC (CWE-285)**
4. **Client-Controlled Payment Amount (CWE-602)**
5. **Concurrent Slot Reservation Race Condition (CWE-362)**
6. **Insecure Direct Object Reference / IDOR (CWE-639)**

---

## 🛠️ Tech Stack

- **Backend:** Python 3.12, Flask 3.1, Werkzeug
- **Database:** SQLite with atomic parameterized transactions
- **Frontend:** HTML5, Modern CSS3 (Dark/Cyan/Green cyber theme), Vanilla JavaScript
- **Security Tools:** Bandit 1.9.4 (SAST), pip-audit 2.10.1 (SCA/SBOM)
- **Testing:** pytest 9.1 (Unit, Concurrency, RBAC, IDOR, Fuzzing, E2E)
- **Containers:** Docker (Multi-stage, unprivileged user UID 10001, read-only rootfs)
- **Orchestration:** Kubernetes / Minikube (Deployment, Service, Secret, ConfigMap, Namespace)
- **CI/CD:** GitHub Actions Automated Pipeline

---

## 🔑 Demo Credentials

| Role | Username | Password | Purpose |
|:---|:---|:---|:---|
| **Administrator** | `admin` | `Admin@Secure2026!` | Fleet command, power limits, audit logs |
| **EV Driver** | `user1` | `User1@Secure2026!` | Standard reservations, charging, payments |
| **EV Driver** | `sharon` | `Sharon@Secure2026!` | Concurrency / multi-user testing |

*Note: The login page includes one-click quick-fill buttons for immediate laboratory demonstration!*

---

## 💻 Quick Start (Local Setup)

### 1. Clone & Set Up Environment
```bash
git clone https://github.com/Sharon/EVChargeSecure.git
cd EVChargeSecure

# Install required dependencies
pip install -r requirements-dev.txt
```

### 2. Initialize and Seed Demo Database
```bash
python seed_data.py
```

### 3. Run Application Server
```bash
python run.py
```
Open your browser and navigate to: **`http://127.0.0.1:5000`**

---

## 🧪 Automated Testing & Verification

Run the full automated test suite (27 comprehensive tests):
```bash
python -m pytest
```

### Test Coverage Highlights:
- `test_auth.py`: Registration, password strength enforcement, brute-force lockout, session regeneration.
- `test_reservations.py`: Available terminal booking, single active reservation limit, cancellation.
- `test_concurrency.py`: Concurrent multi-threaded slot booking race condition verification.
- `test_authorization_idor.py`: RBAC admin protection and horizontal object ownership isolation.
- `test_payments.py`: Authoritative pricing, rejection of tampered client prices, duplicate prevention.
- `test_fuzzing.py`: Injection payloads (SQLi, XSS, long buffers, format strings, malformed IDs).
- `test_integration_e2e.py`: Full end-to-end user lifecycle from registration to settlement.
- `test_vulnerabilities_comparison.py`: Validation of all 6 lab vulnerability demonstrations.

---

## 🛡️ Security Scanners

### 1. Static Application Security Testing (Bandit)
Scan source code for security vulnerabilities:
```bash
bandit -r app/ -c bandit.yaml
```
*Current result: 0 Issues Identified (Clean)*

### 2. Dependency Vulnerability Audit (pip-audit)
Scan third-party packages against the OSV / PyPI vulnerability database:
```bash
pip-audit -r requirements.txt
```
*Current result: 0 Known Vulnerabilities Found (Clean)*

---

## 🐳 Docker Deployment

The application includes a production-hardened Dockerfile:
- **Base image:** `python:3.12-slim`
- **Execution user:** Non-root `appuser` (UID `10001`)
- **Port:** 5000
- **Healthcheck:** Configured on `/auth/login`

### Build & Run Container:
```bash
# Build hardened Docker image
docker build -t evchargesecure:latest .

# Run container with environment configuration
docker run -d \
  --name evcharge-app \
  -p 5000:5000 \
  -e FLASK_ENV=production \
  -e EV_SECRET_KEY="production-secure-random-key" \
  evchargesecure:latest
```

---

## ☸️ Kubernetes / Minikube Deployment

Manifests are organized in `k8s/`:
- `k8s/namespace.yaml`: Enforces Pod Security Standard (Restricted)
- `k8s/secret.yaml`: Injects sensitive keys
- `k8s/configmap.yaml`: Injects non-sensitive environment variables
- `k8s/deployment.yaml`: Enforces non-root UID 10001, `readOnlyRootFilesystem: true`, resource limits, and health probes
- `k8s/service.yaml`: Exposes ClusterIP service on port 5000

### Deploy Manifests:
```bash
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/secret.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml

# Check deployment status
kubectl get all -n evcharge-secure

# Forward port for local access (if using Minikube)
kubectl port-forward -n evcharge-secure svc/evcharge-service 5000:5000
```

---

## 🔄 GitHub Actions CI/CD Pipeline

The workflow defined in `.github/workflows/ci.yml` automatically triggers on `push` and `pull_request`:
1. **Automated Testing:** Runs `pytest` on Python 3.12.
2. **SAST Scan:** Executes `bandit` AST security analysis.
3. **SCA Audit:** Executes `pip-audit` against `requirements.txt`.
4. **Container Build:** Builds Docker image using Buildx.
5. **Kubernetes Validation:** Validates all manifests in `k8s/` using `kubectl --dry-run=client`.

---

## 🔬 Security Laboratory Evaluation Walkthrough

During your laboratory presentation, open the **Security Lab Showcase** in the navigation sidebar:
1. **SQL Injection:** Test `' OR '1'='1' --` in Vulnerable mode (exposing all data) vs Secure mode (safely treated as literal parameter).
2. **Password Storage:** View plaintext storage vs irreversible Scrypt/PBKDF2 salted derivation.
3. **Broken Authorization:** Call administrative hardware function as a `USER` (permitted in vulnerable mode vs rejected with `403 Forbidden` and logged to audit in secure mode).
4. **Payment Tampering:** Submit ₹1.00 for a ₹450.00 session (accepted in vulnerable mode vs overridden by authoritative database total cost in secure mode).
5. **Race Conditions:** Simulate concurrent booking of the same terminal (double booking in vulnerable mode vs single winner with `409 Conflict` in secure mode).
6. **IDOR:** Request session `#42` belonging to another driver (data exposed in vulnerable mode vs horizontal isolation blocking unauthorized access in secure mode).

For full theoretical and threat modeling analysis, see [SECURITY.md](SECURITY.md).
