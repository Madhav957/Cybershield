"""
CyberShield Comprehensive Test Suite
Validates all endpoints, status transitions, database triggers, analyst workflows,
CSRF protection, user authentication, and Role-Based Access Control (RBAC).
"""

import unittest
from werkzeug.security import generate_password_hash
from app import app, get_db, STATUS_TRANSITIONS, FAILED_LOGIN_ATTEMPTS


class CyberShieldTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Seed deterministic test users across roles (ADMIN, ANALYST, VIEWER, DISABLED)."""
        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        try:
            # Map role names to role_ids
            cursor.execute("SELECT role_id, role_name FROM roles")
            roles_map = {r["role_name"]: r["role_id"] for r in cursor.fetchall()}

            test_users = [
                ("Test Administrator", "test_admin", "test_admin@cybershield.local", "TestAdminPass123!", roles_map.get("ADMIN", 1), "ACTIVE"),
                ("Test Analyst", "test_analyst", "test_analyst@cybershield.local", "TestAnalystPass123!", roles_map.get("ANALYST", 2), "ACTIVE"),
                ("Test Viewer", "test_viewer", "test_viewer@cybershield.local", "TestViewerPass123!", roles_map.get("VIEWER", 3), "ACTIVE"),
                ("Test Disabled User", "test_disabled", "test_disabled@cybershield.local", "TestDisabledPass123!", roles_map.get("ANALYST", 2), "DISABLED"),
            ]

            for full_name, username, email, password, role_id, status in test_users:
                cursor.execute("SELECT user_id FROM users WHERE username = %s OR email = %s", (username, email))
                existing = cursor.fetchone()
                hashed = generate_password_hash(password)
                if existing:
                    cursor.execute("""
                        UPDATE users
                        SET full_name = %s, password_hash = %s, role_id = %s, account_status = %s
                        WHERE user_id = %s
                    """, (full_name, hashed, role_id, status, existing["user_id"]))
                else:
                    cursor.execute("""
                        INSERT INTO users (full_name, username, email, password_hash, role_id, account_status, created_at)
                        VALUES (%s, %s, %s, %s, %s, %s, NOW())
                    """, (full_name, username, email, hashed, role_id, status))

            conn.commit()
        finally:
            conn.close()

    @classmethod
    def tearDownClass(cls):
        """Clean up test artifacts and seeded test users from database after tests complete."""
        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM incidents WHERE title LIKE '%Automated Unit Test%' OR title LIKE '%Lifecycle Transition%'")
            cursor.execute("DELETE FROM users WHERE username LIKE 'test_%' OR username = 'new_analyst_user' OR username LIKE 'self_reg_%'")
            conn.commit()
            conn.close()
        except Exception:
            pass

    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = True
        self.app.config["WTF_CSRF_ENABLED"] = False
        self.client = self.app.test_client()
        # Default test client authenticated as test_admin for functional incident/analyst tests
        self.authenticate_client(self.client, username="test_admin", role="ADMIN")
        # Clear rate-limiting tracker before each test
        FAILED_LOGIN_ATTEMPTS.clear()

    def get_csrf_token(self, client):
        with client.session_transaction() as sess:
            if "_csrf_token" not in sess:
                sess["_csrf_token"] = "test-csrf-token-12345"
            return sess["_csrf_token"]

    def authenticate_client(self, client, username="test_admin", role="ADMIN", user_id=1, email="test_admin@cybershield.local"):
        """Directly inject session values to simulate an authenticated user with a specific role."""
        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["username"] = username
            sess["full_name"] = f"Full {username}"
            sess["email"] = email
            sess["role"] = role
            sess["_csrf_token"] = "test-csrf-token-12345"

    # =========================================================================
    # PART 1: Core Functional Tests (Authenticated as ADMIN)
    # =========================================================================

    def test_01_dashboard_loads(self):
        """Test GET / loads dashboard with KPIs, charts, and incident directory."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"CyberShield", response.data)
        self.assertIn(b"Total Incidents", response.data)
        self.assertIn(b"Severity Profile", response.data)
        self.assertIn(b"Lifecycle Status", response.data)
        self.assertIn(b"Attack Vectors", response.data)
        self.assertIn(b"Analyst Workload", response.data)

    def test_02_analysts_roster_loads(self):
        """Test GET /analysts loads roster and investigation counts."""
        response = self.client.get("/analysts")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Security Analyst Command", response.data)
        self.assertIn(b"Arjun Rao", response.data)

    def test_03_audit_history_loads(self):
        """Test GET /audit loads audit ledger."""
        response = self.client.get("/audit")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Incident Status Audit Trail", response.data)

    def test_04_add_incident_form_loads(self):
        """Test GET /incidents/new loads creation form."""
        response = self.client.get("/incidents/new")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Record Security Incident", response.data)
        self.assertIn(b"Attack Vector", response.data)

    def test_05_create_incident_validation_and_success(self):
        """Test POST /incidents/new validation and creation."""
        csrf = self.get_csrf_token(self.client)

        # Missing title should fail
        res_fail = self.client.post("/incidents/new", data={
            "csrf_token": csrf,
            "title": "",
            "attack_type_id": "1",
            "severity": "HIGH",
        }, follow_redirects=True)
        self.assertIn(b"Incident title is required", res_fail.data)

        # Successful creation
        res_success = self.client.post("/incidents/new", data={
            "csrf_token": csrf,
            "title": "Automated Unit Test Incident",
            "description": "Created during automated verification suite",
            "attack_type_id": "1",
            "severity": "CRITICAL",
        }, follow_redirects=True)
        self.assertEqual(res_success.status_code, 200)
        self.assertIn(b"successfully registered", res_success.data)
        self.assertIn(b"Automated Unit Test Incident", res_success.data)

    def test_06_incident_detail_loads(self):
        """Test GET /incidents/1 loads detail view."""
        response = self.client.get("/incidents/1")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Incident Synopsis", response.data)
        self.assertIn(b"Impacted Endpoints", response.data)
        self.assertIn(b"Associated IP Addresses", response.data)

    def test_07_invalid_status_transition_blocked(self):
        """Test that invalid status transitions (e.g. OPEN -> CLOSED) are blocked."""
        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT incident_id, status FROM incidents WHERE status = 'OPEN' LIMIT 1")
        row = cursor.fetchone()
        conn.close()

        if row:
            inc_id = row["incident_id"]
            csrf = self.get_csrf_token(self.client)
            res = self.client.post(f"/incidents/{inc_id}/status", data={
                "csrf_token": csrf,
                "status": "CLOSED",
            }, follow_redirects=True)
            self.assertIn(b"Transition denied", res.data)

    def test_08_analyst_assignment_and_investigation_update(self):
        """Test assigning analyst and updating investigation status & conclusion."""
        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT incident_id FROM incidents ORDER BY incident_id DESC LIMIT 1")
        row = cursor.fetchone()
        inc_id = row["incident_id"]
        conn.close()

        csrf = self.get_csrf_token(self.client)
        # Assign Analyst 1
        res_assign = self.client.post(f"/incidents/{inc_id}/assign", data={
            "csrf_token": csrf,
            "analyst_id": "1",
        }, follow_redirects=True)
        self.assertEqual(res_assign.status_code, 200)
        self.assertIn(b"assigned to Incident", res_assign.data)

        # Update Investigation conclusion
        res_inv = self.client.post(f"/incidents/{inc_id}/investigation", data={
            "csrf_token": csrf,
            "status": "IN_PROGRESS",
            "conclusion": "Forensic memory dump extracted and analyzed.",
        }, follow_redirects=True)
        self.assertEqual(res_inv.status_code, 200)
        self.assertIn(b"Investigation notes and status updated", res_inv.data)

    def test_09_edit_incident(self):
        """Test editing incident title and description."""
        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT incident_id FROM incidents WHERE title LIKE '%Automated Unit Test%' LIMIT 1")
        row = cursor.fetchone()
        conn.close()

        if row:
            inc_id = row["incident_id"]
            csrf = self.get_csrf_token(self.client)
            res = self.client.post(f"/incidents/{inc_id}/edit", data={
                "csrf_token": csrf,
                "title": "Automated Unit Test Incident (Updated)",
                "description": "Updated description during test run",
                "attack_type_id": "2",
                "severity": "HIGH",
            }, follow_redirects=True)
            self.assertEqual(res_status := res.status_code, 200)
            self.assertIn(b"updated successfully", res.data)

    def test_10_csrf_protection_enforcement(self):
        """Test that state-changing POST requests without a valid CSRF token fail."""
        unauth_client = self.app.test_client()
        # Authenticate client
        self.authenticate_client(unauth_client, username="test_admin", role="ADMIN")
        res = unauth_client.post("/incidents/new", data={
            "title": "CSRF Attack Attempt",
            "attack_type_id": "1",
            "severity": "LOW",
        }, follow_redirects=True)
        self.assertIn(b"Security validation failed", res.data)

    def test_11_valid_status_transition_and_audit_trigger(self):
        """Test valid status transition OPEN -> INVESTIGATING and verify audit trigger entry with actor."""
        csrf = self.get_csrf_token(self.client)
        # Create an incident specifically for transition testing
        res_create = self.client.post("/incidents/new", data={
            "csrf_token": csrf,
            "title": "Lifecycle Transition Test Incident",
            "description": "Testing trigger and audit log",
            "attack_type_id": "1",
            "severity": "MEDIUM",
        }, follow_redirects=True)
        self.assertEqual(res_create.status_code, 200)

        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT incident_id FROM incidents WHERE title = 'Lifecycle Transition Test Incident' ORDER BY incident_id DESC LIMIT 1")
        row = cursor.fetchone()
        inc_id = row["incident_id"]
        conn.close()

        # Valid transition: OPEN -> INVESTIGATING
        res_trans = self.client.post(f"/incidents/{inc_id}/status", data={
            "csrf_token": csrf,
            "status": "INVESTIGATING",
        }, follow_redirects=True)
        self.assertIn(b"transition completed", res_trans.data)

        # Open fresh connection to inspect committed trigger changes
        conn2 = get_db()
        cursor2 = conn2.cursor(dictionary=True)
        cursor2.execute("""
            SELECT * FROM incident_status_history
            WHERE incident_id = %s
            ORDER BY history_id DESC LIMIT 1
        """, (inc_id,))
        hist = cursor2.fetchone()
        conn2.close()

        self.assertIsNotNone(hist)
        self.assertEqual(hist["old_status"], "OPEN")
        self.assertEqual(hist["new_status"], "INVESTIGATING")
        self.assertEqual(hist["changed_by"], "test_admin")

    def test_12_link_device_and_ip(self):
        """Test linking devices and IPs to an incident."""
        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT incident_id FROM incidents LIMIT 1")
        inc_id = cursor.fetchone()["incident_id"]
        cursor.execute("SELECT device_id FROM devices LIMIT 1")
        dev_id = cursor.fetchone()["device_id"]
        cursor.execute("SELECT ip_id FROM ip_addresses LIMIT 1")
        ip_id = cursor.fetchone()["ip_id"]
        conn.close()

        csrf = self.get_csrf_token(self.client)

        # Link Device
        res_dev = self.client.post(f"/incidents/{inc_id}/devices", data={
            "csrf_token": csrf,
            "device_id": str(dev_id),
            "impact_description": "Unit test endpoint attachment",
        }, follow_redirects=True)
        self.assertEqual(res_dev.status_code, 200)
        self.assertIn(b"Device successfully linked", res_dev.data)

        # Link IP
        res_ip = self.client.post(f"/incidents/{inc_id}/ips", data={
            "csrf_token": csrf,
            "ip_id": str(ip_id),
            "association_type": "SOURCE",
        }, follow_redirects=True)
        self.assertEqual(res_ip.status_code, 200)
        self.assertIn(b"IP address indicator linked", res_ip.data)

    def test_13_search_and_filtering(self):
        """Test search and filter query parameters on dashboard and audit trail."""
        # Dashboard search
        res_search = self.client.get("/?q=login&severity_filter=HIGH&status_filter=RESOLVED")
        self.assertEqual(res_search.status_code, 200)
        self.assertIn(b"Master Incident Directory", res_search.data)

        # Audit search
        res_audit_filter = self.client.get("/audit?q=test_admin&status_filter=INVESTIGATING")
        self.assertEqual(res_audit_filter.status_code, 200)
        self.assertIn(b"Transition Events", res_audit_filter.data)

    # =========================================================================
    # PART 2: Authentication & Access Control Tests
    # =========================================================================

    def test_14_unauthenticated_user_redirected_to_login(self):
        """Unauthenticated requests to protected endpoints must redirect to /login?next=..."""
        anon_client = self.app.test_client()

        # Dashboard requires auth
        res_dash = anon_client.get("/")
        self.assertEqual(res_dash.status_code, 302)
        self.assertIn("/login", res_dash.headers["Location"])

        # Incident creation requires auth
        res_new = anon_client.get("/incidents/new")
        self.assertEqual(res_new.status_code, 302)
        self.assertIn("/login", res_new.headers["Location"])

        # Incident detail requires auth
        res_det = anon_client.get("/incidents/1")
        self.assertEqual(res_det.status_code, 302)
        self.assertIn("/login", res_det.headers["Location"])

        # Audit trail requires auth
        res_audit = anon_client.get("/audit")
        self.assertEqual(res_audit.status_code, 302)
        self.assertIn("/login", res_audit.headers["Location"])

        # Incident edit requires auth
        res_edit = anon_client.get("/incidents/1/edit")
        self.assertEqual(res_edit.status_code, 302)
        self.assertIn("/login", res_edit.headers["Location"])

    def test_15_login_page_renders_faithfully(self):
        """Test GET /login renders the dedicated login template matching CyberShield identity."""
        anon_client = self.app.test_client()
        res = anon_client.get("/login")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"CyberShield", res.data)
        self.assertIn(b"SECURE ACCESS / CYBERSECURITY OPERATIONS", res.data)
        self.assertIn(b"Welcome back.", res.data)
        self.assertIn(b"login_identifier", res.data)
        self.assertIn(b"password", res.data)
        self.assertIn(b"remember_me", res.data)
        self.assertIn(b"csrf_token", res.data)

    def test_16_login_invalid_credentials_rejected(self):
        """POST /login with bad password returns 401 with generic error message."""
        anon_client = self.app.test_client()
        csrf = self.get_csrf_token(anon_client)
        res = anon_client.post("/login", data={
            "csrf_token": csrf,
            "login_identifier": "test_admin",
            "password": "WrongPassword123!",
        })
        self.assertEqual(res.status_code, 401)
        self.assertIn(b"Invalid username/email or password", res.data)

    def test_17_login_nonexistent_user_rejected(self):
        """POST /login for non-existent user returns 401 with identical generic error."""
        anon_client = self.app.test_client()
        csrf = self.get_csrf_token(anon_client)
        res = anon_client.post("/login", data={
            "csrf_token": csrf,
            "login_identifier": "nonexistent_ghost_user",
            "password": "AnyPassword123!",
        })
        self.assertEqual(res.status_code, 401)
        self.assertIn(b"Invalid username/email or password", res.data)

    def test_18_login_disabled_account_blocked(self):
        """POST /login for user with account_status='DISABLED' returns 403."""
        anon_client = self.app.test_client()
        csrf = self.get_csrf_token(anon_client)
        res = anon_client.post("/login", data={
            "csrf_token": csrf,
            "login_identifier": "test_disabled",
            "password": "TestDisabledPass123!",
        })
        self.assertEqual(res.status_code, 403)
        self.assertIn(b"Account is disabled", res.data)

    def test_19_rate_limiting_locks_out_after_5_failures(self):
        """Brute-force protection: 5 consecutive failed attempts from IP locks out with 429."""
        anon_client = self.app.test_client()
        csrf = self.get_csrf_token(anon_client)

        for attempt in range(5):
            res = anon_client.post("/login", data={
                "csrf_token": csrf,
                "login_identifier": "test_admin",
                "password": f"BadPassword{attempt}!",
            })
            self.assertEqual(res.status_code, 401)

        # 6th attempt should be blocked with 429 Too Many Requests
        res_locked = anon_client.post("/login", data={
            "csrf_token": csrf,
            "login_identifier": "test_admin",
            "password": "TestAdminPass123!",
        })
        self.assertEqual(res_locked.status_code, 429)
        self.assertIn(b"Too many failed login attempts", res_locked.data)

    def test_20_successful_login_with_username(self):
        """Successful login with username creates session, updates last_login, and redirects."""
        anon_client = self.app.test_client()
        csrf = self.get_csrf_token(anon_client)
        res = anon_client.post("/login", data={
            "csrf_token": csrf,
            "login_identifier": "test_admin",
            "password": "TestAdminPass123!",
        }, follow_redirects=False)

        self.assertEqual(res.status_code, 302)
        self.assertEqual(res.headers["Location"], "/")

        with anon_client.session_transaction() as sess:
            self.assertEqual(sess.get("username"), "test_admin")
            self.assertEqual(sess.get("role"), "ADMIN")
            self.assertIsNotNone(sess.get("user_id"))

    def test_21_successful_login_with_email(self):
        """Successful login with email address authenticates identically."""
        anon_client = self.app.test_client()
        csrf = self.get_csrf_token(anon_client)
        res = anon_client.post("/login", data={
            "csrf_token": csrf,
            "login_identifier": "test_analyst@cybershield.local",
            "password": "TestAnalystPass123!",
        }, follow_redirects=False)

        self.assertEqual(res.status_code, 302)
        self.assertEqual(res.headers["Location"], "/")

        with anon_client.session_transaction() as sess:
            self.assertEqual(sess.get("username"), "test_analyst")
            self.assertEqual(sess.get("role"), "ANALYST")

    def test_22_safe_redirect_prevents_open_redirect(self):
        """Login only honors relative internal paths, rejecting external URLs."""
        anon_client = self.app.test_client()
        csrf = self.get_csrf_token(anon_client)

        # Internal safe redirect honored
        res_safe = anon_client.post("/login?next=/audit", data={
            "csrf_token": csrf,
            "login_identifier": "test_admin",
            "password": "TestAdminPass123!",
        }, follow_redirects=False)
        self.assertEqual(res_safe.status_code, 302)
        self.assertEqual(res_safe.headers["Location"], "/audit")

        # External open redirect suppressed -> falls back to "/"
        anon_client2 = self.app.test_client()
        csrf2 = self.get_csrf_token(anon_client2)
        res_unsafe = anon_client2.post("/login?next=https://attacker.evil.com", data={
            "csrf_token": csrf2,
            "login_identifier": "test_admin",
            "password": "TestAdminPass123!",
        }, follow_redirects=False)
        self.assertEqual(res_unsafe.status_code, 302)
        self.assertEqual(res_unsafe.headers["Location"], "/")

    def test_23_logout_clears_session(self):
        """POST /logout clears session and redirects to /login."""
        client = self.app.test_client()
        self.authenticate_client(client, username="test_analyst", role="ANALYST")
        csrf = self.get_csrf_token(client)

        res = client.post("/logout", data={"csrf_token": csrf}, follow_redirects=False)
        self.assertEqual(res.status_code, 302)
        self.assertEqual(res.headers["Location"], "/login")

        with client.session_transaction() as sess:
            self.assertNotIn("user_id", sess)
            self.assertNotIn("username", sess)

    # =========================================================================
    # PART 3: Role-Based Access Control (RBAC) Tests
    # =========================================================================

    def test_24_admin_can_access_register_and_create_users(self):
        """ADMIN role can access GET and POST /register."""
        admin_client = self.app.test_client()
        self.authenticate_client(admin_client, username="test_admin", role="ADMIN")
        csrf = self.get_csrf_token(admin_client)

        # GET /register loads
        res_get = admin_client.get("/register")
        self.assertEqual(res_get.status_code, 200)
        self.assertIn(b"User Administration", res_get.data)
        self.assertIn(b"Provision New Account", res_get.data)

        # POST /register creates a new user
        res_post = admin_client.post("/register", data={
            "csrf_token": csrf,
            "full_name": "New Analyst User",
            "username": "new_analyst_user",
            "email": "new_analyst@cybershield.local",
            "password": "SecurePassword123!",
            "role_id": "2",
            "account_status": "ACTIVE",
        }, follow_redirects=True)
        self.assertEqual(res_post.status_code, 200)
        self.assertIn(b"successfully registered", res_post.data)

    def test_25_analyst_blocked_from_register(self):
        """ANALYST role accessing /register is rejected with 403 Forbidden."""
        analyst_client = self.app.test_client()
        self.authenticate_client(analyst_client, username="test_analyst", role="ANALYST")

        # GET /register returns 403
        res = analyst_client.get("/register")
        self.assertEqual(res.status_code, 403)
        self.assertIn(b"Access Denied", res.data)

    def test_26_viewer_can_view_incidents_and_dashboard(self):
        """VIEWER role can view dashboard, analyst roster, and incident details in read-only mode."""
        viewer_client = self.app.test_client()
        self.authenticate_client(viewer_client, username="test_viewer", role="VIEWER")

        # Can view dashboard
        res_dash = viewer_client.get("/")
        self.assertEqual(res_dash.status_code, 200)
        self.assertIn(b"CyberShield", res_dash.data)

        # Can view analyst roster
        res_analysts = viewer_client.get("/analysts")
        self.assertEqual(res_analysts.status_code, 200)

        # Can view incident detail
        res_detail = viewer_client.get("/incidents/1")
        self.assertEqual(res_detail.status_code, 200)

        # Can view audit trail
        res_audit = viewer_client.get("/audit")
        self.assertEqual(res_audit.status_code, 200)

    def test_27_viewer_blocked_from_mutations(self):
        """VIEWER role is blocked with 403 Forbidden from all mutation endpoints."""
        viewer_client = self.app.test_client()
        self.authenticate_client(viewer_client, username="test_viewer", role="VIEWER")
        csrf = self.get_csrf_token(viewer_client)

        # 1. Blocked from GET /incidents/new
        res1 = viewer_client.get("/incidents/new")
        self.assertEqual(res1.status_code, 403)

        # 2. Blocked from POST /incidents/new
        res2 = viewer_client.post("/incidents/new", data={
            "csrf_token": csrf,
            "title": "Viewer Breach Attempt",
            "attack_type_id": "1",
            "severity": "LOW",
        })
        self.assertEqual(res2.status_code, 403)

        # 3. Blocked from POST /incidents/1/status
        res3 = viewer_client.post("/incidents/1/status", data={
            "csrf_token": csrf,
            "status": "INVESTIGATING",
        })
        self.assertEqual(res3.status_code, 403)

        # 4. Blocked from POST /incidents/1/edit
        res4 = viewer_client.post("/incidents/1/edit", data={
            "csrf_token": csrf,
            "title": "Viewer Mod Attempt",
            "attack_type_id": "1",
            "severity": "LOW",
        })
        self.assertEqual(res4.status_code, 403)

        # 5. Blocked from POST /incidents/1/assign
        res5 = viewer_client.post("/incidents/1/assign", data={
            "csrf_token": csrf,
            "analyst_id": "1",
        })
        self.assertEqual(res5.status_code, 403)

        # 6. Blocked from POST /incidents/1/investigation
        res6 = viewer_client.post("/incidents/1/investigation", data={
            "csrf_token": csrf,
            "status": "COMPLETED",
        })
        self.assertEqual(res6.status_code, 403)

        # 7. Blocked from POST /incidents/1/devices
        res7 = viewer_client.post("/incidents/1/devices", data={
            "csrf_token": csrf,
            "device_id": "1",
        })
        self.assertEqual(res7.status_code, 403)

        # 8. Blocked from POST /incidents/1/ips
        res8 = viewer_client.post("/incidents/1/ips", data={
            "csrf_token": csrf,
            "ip_id": "1",
        })
        self.assertEqual(res8.status_code, 403)

        # 9. Blocked from GET /register
        res9 = viewer_client.get("/register")
        self.assertEqual(res9.status_code, 403)

    # =========================================================================
    # PART 4: Public Self-Registration Tests
    # =========================================================================

    def test_28_public_self_registration_page_renders(self):
        """Unauthenticated visitor can load GET /register and sees the public signup form."""
        anon_client = self.app.test_client()
        res = anon_client.get("/register")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Create your account", res.data)
        self.assertIn(b"Full Name", res.data)
        self.assertIn(b"Username", res.data)
        self.assertIn(b"Corporate Email", res.data)
        self.assertIn(b"Operational Role", res.data)
        self.assertIn(b"Password", res.data)
        self.assertIn(b"Confirm Password", res.data)

    def test_29_public_self_registration_validation(self):
        """Validation failures (passwords do not match, < 8 chars, missing fields) return 400."""
        anon_client = self.app.test_client()
        csrf = self.get_csrf_token(anon_client)

        # Mismatched passwords
        res_mismatch = anon_client.post("/register", data={
            "csrf_token": csrf,
            "full_name": "Self Reg User",
            "username": "self_reg_mismatch",
            "email": "mismatch@cybershield.local",
            "password": "Password123!",
            "confirm_password": "DifferentPassword123!",
            "role_id": "2",
        })
        self.assertEqual(res_mismatch.status_code, 400)
        self.assertIn(b"Passwords do not match", res_mismatch.data)

        # Password too short (< 8 chars)
        res_short = anon_client.post("/register", data={
            "csrf_token": csrf,
            "full_name": "Self Reg User",
            "username": "self_reg_short",
            "email": "short@cybershield.local",
            "password": "short",
            "confirm_password": "short",
            "role_id": "2",
        })
        self.assertEqual(res_short.status_code, 400)
        self.assertIn(b"at least 8 characters", res_short.data)

    def test_30_public_self_registration_duplicate_check(self):
        """Registering with an existing username or email returns 400 with duplicate notice."""
        anon_client = self.app.test_client()
        csrf = self.get_csrf_token(anon_client)

        # Try duplicate username
        res_dup_user = anon_client.post("/register", data={
            "csrf_token": csrf,
            "full_name": "Imposter User",
            "username": "test_admin",
            "email": "imposter@cybershield.local",
            "password": "ValidPassword123!",
            "confirm_password": "ValidPassword123!",
            "role_id": "2",
        })
        self.assertEqual(res_dup_user.status_code, 400)
        self.assertIn(b"already taken", res_dup_user.data)

        # Try duplicate email
        res_dup_email = anon_client.post("/register", data={
            "csrf_token": csrf,
            "full_name": "Imposter Email User",
            "username": "imposter_username_unique",
            "email": "test_admin@cybershield.local",
            "password": "ValidPassword123!",
            "confirm_password": "ValidPassword123!",
            "role_id": "2",
        })
        self.assertEqual(res_dup_email.status_code, 400)
        self.assertIn(b"already registered", res_dup_email.data)

    def test_31_public_self_registration_success_and_auto_login(self):
        """Public self-registration creates the account, establishes session, and redirects to dashboard."""
        anon_client = self.app.test_client()
        csrf = self.get_csrf_token(anon_client)

        res = anon_client.post("/register", data={
            "csrf_token": csrf,
            "full_name": "Self Registered Analyst",
            "username": "self_reg_analyst",
            "email": "analyst@selfreg.local",
            "password": "AnalystSecure123!",
            "confirm_password": "AnalystSecure123!",
            "role_id": "2",
        }, follow_redirects=False)

        self.assertEqual(res.status_code, 302)
        self.assertEqual(res.headers["Location"], "/")

        with anon_client.session_transaction() as sess:
            self.assertEqual(sess.get("username"), "self_reg_analyst")
            self.assertEqual(sess.get("role"), "ANALYST")
            self.assertIsNotNone(sess.get("user_id"))

    def test_32_public_self_registration_role_escalation_blocked(self):
        """Attempting to tamper with role_id=1 (ADMIN) during self-registration forces role to ANALYST."""
        anon_client = self.app.test_client()
        csrf = self.get_csrf_token(anon_client)

        res = anon_client.post("/register", data={
            "csrf_token": csrf,
            "full_name": "Sneaky User",
            "username": "self_reg_sneaky",
            "email": "sneaky@selfreg.local",
            "password": "SneakySecure123!",
            "confirm_password": "SneakySecure123!",
            "role_id": "1",  # Attempting to assign ADMIN role
        }, follow_redirects=False)

        self.assertEqual(res.status_code, 302)

        with anon_client.session_transaction() as sess:
            # Must NOT be ADMIN, forced to ANALYST
            self.assertEqual(sess.get("role"), "ANALYST")


if __name__ == "__main__":
    unittest.main()
