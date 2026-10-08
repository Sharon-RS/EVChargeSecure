# EVChargeSecure – Comprehensive Security Architecture & Vulnerability Analysis

**Academic Course:** Secure Software Engineering  
**Project:** EVChargeSecure – Secure EV Charging Station Management System  
**Framework:** Flask / Python 3.12 / SQLite / Docker / Kubernetes / Bandit / pip-audit  

---

## 1. Executive Summary & Security Posture

EVChargeSecure is an enterprise-grade, secure electric vehicle charging station management system built according to Secure Software Development Lifecycle (SSDLC) principles. It provides end-to-end functionality for EV drivers and fleet administrators while mitigating critical application security risks identified in the **OWASP Top 10** and **CWE Top 25**.

### Key Defense Implementations:
- **Zero-Trust Role-Based Access Control (RBAC):** Distinct `USER` and `ADMIN` operational boundaries enforced via cryptographically verified sessions and decorators.
- **Horizontal Access Scoping (Anti-IDOR):** Strict user-session ownership verification on all charging sessions, slot bookings, and financial receipts (`WHERE id = ? AND user_id = ?`).
- **Atomic Concurrency Arbitrage:** Concurrency race conditions in charging point reservations are eliminated through single-statement test-and-set transactions.
- **Authoritative Server Pricing:** Zero trust in client-side telemetry; energy consumption and invoices are strictly calculated server-side based on immutable meter formulas and database tariffs.
- **Defense-in-Depth Storage:** Passwords hashed with Scrypt/PBKDF2 salted derivations; SQL queries strictly parameterized.
- **Sanitized Security Audit Logging:** Audit trail recording authentication, authorization failures, hardware state changes, and financial settlements while redacting sensitive tokens and credentials.
- **Container & Orchestration Hardening:** Non-root execution (UID 10001), Read-Only root filesystem, minimal image layers, and dropped capabilities.

---

## 2. Threat Modeling & Attack Surface

```
[ EV Driver / Client Browser ] 
              │
              ▼ HTTPS / CSRF Token / SameSite Cookie
┌────────────────────────────────────────────────────────┐
│                   Reverse Proxy / Ingress              │
│       (Security Headers: CSP, X-Frame-Options, HSTS)   │
└──────────────────────────┬─────────────────────────────┘
                           ▼ Port 5000 (Internal ClusterIP)
┌────────────────────────────────────────────────────────┐
│                  Flask Application Core                │
│  ├─ Authentication Middleware (Rate Limit & Lockout)    │
│  ├─ RBAC Gatekeeper (@admin_required, @login_required)  │
│  ├─ CSRF Validation Filter                             │
│  ├─ Business Logic (Server Billing Engine & Atomic Lock)│
│  └─ Audit Dispatcher (Sanitizer & Event Log)           │
└──────────────────────────┬─────────────────────────────┘
                           ▼ Parameterized SQLite Interface
┌────────────────────────────────────────────────────────┐
│             Isolated SQLite Database Engine            │
│       (users, stations, charging_points, audit_logs)   │
└────────────────────────────────────────────────────────┘
```

---

## 3. Detailed Vulnerability Demonstration & Mitigation Matrix

To satisfy academic assessment requirements, EVChargeSecure models six core software vulnerabilities identified during threat modeling, implements their hardened production mitigations, and provides automated test harnesses in `tests/test_vulnerabilities_comparison.py` as well as an interactive laboratory sandbox at `/security-lab`.

### Vulnerability 1: SQL Injection (SQLi)
* **CWE Classification:** [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
* **Threat Scenario:** In the station search feature, user input is passed into dynamic SQL queries without parameterized isolation. An attacker submits `' OR '1'='1' --` to enumerate unreleased station records or manipulate queries.
* **Before (Vulnerable):**
  ```python
  # Dynamic string formatting enables query structure manipulation
  raw_sql = f"SELECT id, name, location FROM stations WHERE name LIKE '%{query}%'"
  results = cursor.execute(raw_sql).fetchall()
  ```
* **After (Secure Production):**
  ```python
  # SQLite engine compiles query structure; input treated strictly as literal data parameter
  safe_sql = "SELECT id, name, location FROM stations WHERE name LIKE ?"
  results = cursor.execute(safe_sql, (f"%{query}%",)).fetchall()
  ```
* **Differential Analysis:**
  - *Attacker impact before:* Full database compromise, authentication bypass, data exfiltration.
  - *Remediation result:* SQLite parameter binding treats the quote character as literal data. Injection attempts yield zero matched rows or safe literals.

---

### Vulnerability 2: Plaintext Password Storage
* **CWE Classification:** [CWE-256: Plaintext Storage of a Password](https://cwe.mitre.org/data/definitions/256.html) / [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
* **Threat Scenario:** Driver and administrator passwords stored as unencrypted text strings. If database backups are inadvertently exposed or accessed via unauthorized read, all credentials are instantly compromised.
* **Before (Vulnerable):**
  ```python
  cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
  ```
* **After (Secure Production):**
  ```python
  from werkzeug.security import generate_password_hash, check_password_hash
  # High cost factor Scrypt/PBKDF2 with unique cryptographic salt per user
  password_hash = generate_password_hash(password)
  cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
  ```
* **Differential Analysis:**
  - *Attacker impact before:* Immediate credential reuse attacks across platforms.
  - *Remediation result:* Irreversible one-way cryptographic transformation. Even with full database access, precomputed rainbow table attacks fail due to salted entropy.

---

### Vulnerability 3: Broken Function-Level Authorization (Missing RBAC)
* **CWE Classification:** [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
* **Threat Scenario:** Hardware configuration endpoints (such as `/admin/points/<id>/update` to adjust terminal power limits from 22 kW to 350 kW) verify that a caller is authenticated, but fail to check if the caller possesses the `ADMIN` role. An unprivileged driver could alter electrical load parameters, posing electrical grid hazards.
* **Before (Vulnerable):**
  ```python
  @app.route("/admin/points/<id>/update", methods=["POST"])
  @login_required  # Only checks if user is logged in!
  def update_point(id):
      set_hardware_power(...) # Standard user can execute!
  ```
* **After (Secure Production):**
  ```python
  @app.route("/admin/points/<id>/update", methods=["POST"])
  @admin_required  # Strictly asserts session.get('role') == 'ADMIN'
  @csrf_protect
  def update_point(id):
      set_hardware_power(...)
  ```
* **Differential Analysis:**
  - *Attacker impact before:* Horizontal and vertical privilege escalation; unauthorized modification of physical power parameters.
  - *Remediation result:* `@admin_required` validates `role == 'ADMIN'`, terminates unauthorized requests with `403 Forbidden`, and writes an `AUTHORIZATION_FAILURE` record to the audit log.

---

### Vulnerability 4: Client-Controlled Payment Amount (Business Logic Flaw)
* **CWE Classification:** [CWE-602: Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html)
* **Threat Scenario:** During invoice settlement, the application relies on an `amount` parameter submitted in the client HTTP POST body. A malicious driver dispenses 45 kWh (worth ₹810.00) but edits the form payload to `amount=1.00`, defrauding the charging network operator.
* **Before (Vulnerable):**
  ```python
  amount = float(request.form.get("amount")) # Blindly trusts client!
  cursor.execute("INSERT INTO payments (amount) VALUES (?)", (amount,))
  ```
* **After (Secure Production):**
  ```python
  # Server retrieves authoritative energy and tariff directly from the completed session record
  session_data = db.execute("SELECT total_cost FROM charging_sessions WHERE id = ? AND user_id = ?", (session_id, user_id)).fetchone()
  authorized_amount = session_data["total_cost"] # Client amount ignored!
  cursor.execute("INSERT INTO payments (amount) VALUES (?)", (authorized_amount,))
  ```
* **Differential Analysis:**
  - *Attacker impact before:* Direct financial loss, fraudulent checkout.
  - *Remediation result:* Zero client trust. Total cost is derived exclusively on the backend (`energy_kwh * tariff_per_kwh`). Any discrepancy is flagged in the security audit log.

---

### Vulnerability 5: Concurrent Reservation Race Condition (TOCTOU)
* **CWE Classification:** [CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization](https://cwe.mitre.org/data/definitions/362.html)
* **Threat Scenario:** Two drivers simultaneously attempt to reserve the last remaining fast-charging connector at Chennai Central. In a standard time-of-check to time-of-use (TOCTOU) architecture, both requests query availability, see `AVAILABLE`, and proceed to issue an `INSERT INTO reservations`, resulting in a double-booked physical connector.
* **Before (Vulnerable):**
  ```python
  # Non-atomic check and update
  point = db.execute("SELECT status FROM charging_points WHERE id = ?", (point_id,)).fetchone()
  if point["status"] == "AVAILABLE":
      # Execution context switch occurs here
      cursor.execute("UPDATE charging_points SET status = 'RESERVED' WHERE id = ?", (point_id,))
      cursor.execute("INSERT INTO reservations ...")
  ```
* **After (Secure Production):**
  ```python
  # Atomic Test-and-Set Lock
  cursor.execute("""
      UPDATE charging_points 
      SET status = 'RESERVED' 
      WHERE id = ? AND status = 'AVAILABLE'
  """, (point_id,))
  if cursor.rowcount == 0:
      # Another concurrent thread won the race
      log_audit_event("RESERVATION_CONFLICT", ...)
      return "Conflict: Terminal already locked", 409
  cursor.execute("INSERT INTO reservations ...")
  db.commit()
  ```
* **Differential Analysis:**
  - *Attacker impact before:* Physical operational conflict; customer dissatisfaction; system state inconsistency.
  - *Remediation result:* SQLite's row-level update isolation guarantees that exactly one transaction succeeds. The competing request receives `409 Conflict`.

---

### Vulnerability 6: Insecure Direct Object Reference (IDOR)
* **CWE Classification:** [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
* **Threat Scenario:** A user modifies the numeric URL parameter in `/user/receipt/<payment_id>` or `/user/charging/session/<session_id>` to view another driver's charging habits, location history, vehicle telemetry, and payment receipts.
* **Before (Vulnerable):**
  ```python
  @app.route("/user/receipt/<int:payment_id>")
  @login_required
  def receipt(payment_id):
      # Blind lookup by ID without asserting ownership
      payment = db.execute("SELECT * FROM payments WHERE id = ?", (payment_id,)).fetchone()
      return render_template("receipt.html", payment=payment)
  ```
* **After (Secure Production):**
  ```python
  @app.route("/user/receipt/<int:payment_id>")
  @login_required
  def receipt(payment_id):
      # Strict scoping to authenticated caller's user_id
      payment = db.execute("SELECT * FROM payments WHERE id = ? AND user_id = ?", 
                           (payment_id, session["user_id"])).fetchone()
      if not payment:
          log_audit_event("AUTHORIZATION_FAILURE", "IDOR attempt intercepted", severity="SECURITY_ALERT")
          return redirect(...)
      return render_template("receipt.html", payment=payment)
  ```
* **Differential Analysis:**
  - *Attacker impact before:* Massive personally identifiable information (PII) leak, violation of user privacy regulations (GDPR/DPDP).
  - *Remediation result:* Object lookups are bound to the authenticated session context. Cross-tenant reads return `404/Access Denied` and trigger security alerts.

---

## 4. Container & Orchestration Hardening

### Docker Security Features
1. **Lightweight Base Image:** Utilizes `python:3.12-slim` to eliminate unnecessary binaries, shells, and package managers that expand the attack surface.
2. **Unprivileged Execution:** Runs under custom user and group `appuser:appgroup` (UID `10001:10001`). No root privileges exist within the container.
3. **No Hard-Coded Credentials:** All secrets (session keys, database paths) are supplied via environment injection.
4. **Health Check Probing:** Native `HEALTHCHECK` instructions ensuring responsive HTTP endpoint availability without leaking information.

### Kubernetes Security Controls
1. **Pod Security Standards (Restricted):**
   - `seccompProfile: RuntimeDefault`
   - `capabilities: drop: ["ALL"]`
   - `allowPrivilegeEscalation: false`
2. **Read-Only Root Filesystem:**
   - Container root filesystem is mounted as read-only (`readOnlyRootFilesystem: true`).
   - Writable directories (`/app/data` for database storage and `/tmp`) are backed by isolated `emptyDir` volumes.
3. **Resource Quotas & Limits:**
   - Guaranteed resource boundaries (`limits: cpu: 500m, memory: 256Mi`) prevent noisy-neighbor and DoS starvation vectors.
4. **Secrets Separation:**
   - Cryptographic keys reside in native Kubernetes `Secret` resources, completely separated from application code.

---

## 5. Security Scanning & Verification Results

| Security Tool | Scan Target | Target Standard | Result | Status |
|:---|:---|:---|:---|:---|
| **pytest** | 27 Automated Tests | Functional, Concurrency, RBAC, IDOR, Fuzzing | 27 Passed / 0 Failed | **PASS (100%)** |
| **Bandit** | `app/` Source Code | AST Static Application Security Testing (SAST) | 0 Issues (Low: 0, Med: 0, High: 0) | **PASS (Clean)** |
| **pip-audit** | `requirements.txt` | Software Bill of Materials (SBOM) / CVE Scanner | 0 Known Vulnerabilities | **PASS (Clean)** |
| **K8s Dry-Run**| `k8s/*.yaml` | Kubernetes Client & Schema Validation | 5 Manifests Validated | **PASS (Valid)** |

---

## 6. Audit Logging & Sanitization Policy

The application maintains an immutable audit log table (`audit_logs`) tracking security and operational occurrences:
- `LOGIN_SUCCESS`, `LOGIN_FAILED`, `ACCOUNT_LOCKED`
- `AUTHORIZATION_FAILURE`, `CSRF_VIOLATION`
- `RESERVATION_CREATED`, `RESERVATION_CONFLICT`, `RESERVATION_CANCELLED`
- `CHARGING_STARTED`, `CHARGING_STOPPED`, `PAYMENT_COMPLETED`
- `ADMIN_ACTION`, `MAINTENANCE_CREATED`, `MAINTENANCE_RESOLVED`

**Sanitization Rule:** All audit text is filtered through `sanitize_audit_text()` before insertion, stripping passwords, card numbers, session tokens, and authentication headers.
