"""
CyberShield - Cybersecurity Incident Intelligence System
========================================================
A centralized cybersecurity incident operations platform.
Backend: Python 3 / Flask
Database: MySQL
Frontend: HTML5, CSS3, Bootstrap 5, Chart.js
"""

import os
import secrets
import logging
import functools
from datetime import datetime, timedelta
from typing import Dict, Any, Tuple, List, Optional
import click
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
from mysql.connector import errorcode
from dotenv import load_dotenv
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    abort,
    jsonify,
)

# Load environment configuration
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "cybershield-dev-secret-key-change-in-prod-38bdf8")

# Secure Session Cookie Settings & Lifetime
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=12)

# Logging setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# Database Connection Settings
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DB_CONFIG: Dict[str, Any] = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", "3306")),
    "user": os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASSWORD", ""),
    "database": os.getenv("DB_NAME", "cybershield"),
}

# Configure SSL using CA certificate if provided (for secure cloud database e.g., Aiven MySQL)
ssl_ca_env = os.getenv("DB_SSL_CA")
if ssl_ca_env:
    ca_path = ssl_ca_env if os.path.isabs(ssl_ca_env) else os.path.abspath(os.path.join(BASE_DIR, ssl_ca_env))
    if not os.path.exists(ca_path):
        # Fallback check for space variations (e.g., "ca(1).pem" vs "ca (1).pem")
        if "ca(1).pem" in ca_path:
            alt_path = ca_path.replace("ca(1).pem", "ca (1).pem")
            if os.path.exists(alt_path):
                ca_path = alt_path
        elif "ca (1).pem" in ca_path:
            alt_path = ca_path.replace("ca (1).pem", "ca(1).pem")
            if os.path.exists(alt_path):
                ca_path = alt_path

    if os.path.exists(ca_path):
        DB_CONFIG["ssl_ca"] = ca_path
        DB_CONFIG["ssl_verify_cert"] = True
    else:
        logging.warning("Configured DB_SSL_CA certificate file not found.")

# Permitted Incident Status Transition State Machine
STATUS_TRANSITIONS = {
    "OPEN": ["INVESTIGATING"],
    "INVESTIGATING": ["CONTAINED", "RESOLVED"],
    "CONTAINED": ["INVESTIGATING", "RESOLVED"],
    "RESOLVED": ["CLOSED"],
    "CLOSED": [],
}

VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
VALID_STATUSES = set(STATUS_TRANSITIONS.keys())
VALID_INVESTIGATION_STATUSES = {"ASSIGNED", "IN_PROGRESS", "COMPLETED"}


# -----------------------------------------------------------------------------
# Zero-Dependency CSRF Protection & Security Headers
# -----------------------------------------------------------------------------

def generate_csrf_token() -> str:
    """Generate or retrieve a cryptographically secure CSRF token for the session."""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


app.jinja_env.globals["csrf_token"] = generate_csrf_token


# -----------------------------------------------------------------------------
# Rate Limiting & Brute-Force Protection
# -----------------------------------------------------------------------------
FAILED_LOGIN_ATTEMPTS: Dict[str, List[datetime]] = {}
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=5)
ATTEMPT_WINDOW = timedelta(minutes=15)


def is_rate_limited(ip: str) -> bool:
    """Check whether client IP has exceeded failed login threshold within window."""
    now = datetime.now()
    attempts = FAILED_LOGIN_ATTEMPTS.get(ip, [])
    recent_attempts = [t for t in attempts if now - t < ATTEMPT_WINDOW]
    FAILED_LOGIN_ATTEMPTS[ip] = recent_attempts
    if len(recent_attempts) >= MAX_FAILED_ATTEMPTS:
        if now - recent_attempts[-1] < LOCKOUT_DURATION:
            return True
    return False


def record_failed_attempt(ip: str) -> None:
    """Record timestamp of failed login attempt for the given IP address."""
    now = datetime.now()
    if ip not in FAILED_LOGIN_ATTEMPTS:
        FAILED_LOGIN_ATTEMPTS[ip] = []
    FAILED_LOGIN_ATTEMPTS[ip].append(now)


def clear_failed_attempts(ip: str) -> None:
    """Reset failed login history upon successful user authentication."""
    FAILED_LOGIN_ATTEMPTS.pop(ip, None)


# -----------------------------------------------------------------------------
# Security & Authorization Helper Functions
# -----------------------------------------------------------------------------

def is_safe_url(target: Optional[str]) -> bool:
    """Ensure redirection targets only internal relative paths to prevent open redirects."""
    if not target:
        return False
    return target.startswith("/") and not target.startswith("//")


def get_user_by_identifier(identifier: str) -> Optional[Dict[str, Any]]:
    """Retrieve user credentials, account status, and role name by username or email."""
    conn = get_db()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT u.user_id, u.full_name, u.username, u.email, u.password_hash,
                   u.role_id, u.account_status, u.last_login, r.role_name
            FROM users u
            JOIN roles r ON u.role_id = r.role_id
            WHERE u.username = %s OR u.email = %s
            LIMIT 1
        """, (identifier, identifier))
        return cursor.fetchone()
    finally:
        conn.close()


@app.context_processor
def inject_user() -> Dict[str, Any]:
    """Expose authenticated user identity and role globally across Jinja templates."""
    if session.get("user_id"):
        return {
            "current_user": {
                "user_id": session.get("user_id"),
                "username": session.get("username"),
                "full_name": session.get("full_name"),
                "email": session.get("email"),
                "role": session.get("role"),
                "is_authenticated": True,
            }
        }
    return {
        "current_user": {
            "is_authenticated": False,
            "role": None,
        }
    }


def login_required(view_func):
    """Enforce user authentication before granting access to protected routes."""
    @functools.wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if not session.get("user_id"):
            if request.method == "GET":
                next_target = request.full_path if request.query_string else request.path
                return redirect(url_for("login", next=next_target))
            flash("Authentication required. Please sign in to proceed.", "error")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapped_view


def role_required(*allowed_roles: str):
    """Enforce Role-Based Access Control (RBAC) on protected endpoints."""
    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapped_view(*args, **kwargs):
            if not session.get("user_id"):
                return redirect(url_for("login", next=request.path))
            user_role = session.get("role")
            if user_role not in allowed_roles:
                app.logger.warning(
                    "Access denied for user '%s' (role: %s) to path: %s (permitted: %s)",
                    session.get("username"),
                    user_role,
                    request.path,
                    allowed_roles,
                )
                flash(f"Access denied: '{user_role}' role lacks permission for this action.", "error")
                abort(403)
            return view_func(*args, **kwargs)
        return wrapped_view
    return decorator


@app.errorhandler(403)
def forbidden_error(error):
    """Render custom branded 403 Forbidden page for unauthorized access attempts."""
    return render_template("403.html"), 403


@app.before_request
def verify_csrf() -> None:
    """Enforce CSRF token verification for all state-changing HTTP requests."""
    if request.method in ["POST", "PUT", "PATCH", "DELETE"]:
        token = request.form.get("csrf_token")
        expected = session.get("_csrf_token")
        if not token or not expected or not secrets.compare_digest(token, expected):
            app.logger.warning("CSRF token verification failed for path: %s", request.path)
            flash("Security validation failed (invalid or expired CSRF token). Please retry.", "error")
            if request.path in ["/login", "/register"]:
                return redirect(request.path)
            fallback = url_for("dashboard") if session.get("user_id") else url_for("login")
            return redirect(request.referrer or fallback)


@app.after_request
def set_security_headers(response):
    """Set essential security headers on outgoing HTTP responses."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


# -----------------------------------------------------------------------------
# Database Utility Helper
# -----------------------------------------------------------------------------

def get_db():
    """Establish and return an active MySQL connection with dictionary cursor support."""
    return mysql.connector.connect(**DB_CONFIG)


# -----------------------------------------------------------------------------
# Data Access Functions (Parameterized & Validated)
# -----------------------------------------------------------------------------

def get_dashboard_data(filters: Dict[str, str]) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Retrieve live dashboard KPI statistics, filtered incidents, and attack types from MySQL.
    """
    connection = get_db()
    try:
        cursor = connection.cursor(dictionary=True)

        # 1. Real-time KPI Statistics
        cursor.execute("""
            SELECT
                COUNT(*) AS total,
                COALESCE(SUM(status = 'OPEN'), 0) AS count_open,
                COALESCE(SUM(status = 'INVESTIGATING'), 0) AS count_investigating,
                COALESCE(SUM(status = 'CONTAINED'), 0) AS count_contained,
                COALESCE(SUM(status = 'RESOLVED'), 0) AS count_resolved,
                COALESCE(SUM(status = 'CLOSED'), 0) AS count_closed,
                COALESCE(SUM(severity = 'CRITICAL'), 0) AS count_critical,
                COALESCE(SUM(severity = 'HIGH'), 0) AS count_high,
                COALESCE(SUM(severity IN ('CRITICAL', 'HIGH')), 0) AS count_critical_high,
                COALESCE(SUM(status IN ('OPEN', 'INVESTIGATING', 'CONTAINED')), 0) AS count_active
            FROM incidents
        """)
        raw_stats = cursor.fetchone() or {}
        # Convert Decimal values to int for consistent template and JSON usage
        stats = {k: int(v) if v is not None else 0 for k, v in raw_stats.items()}

        # 2. Attack Types list
        cursor.execute("SELECT attack_type_id, type_name, description FROM attack_types ORDER BY type_name ASC")
        attack_types = cursor.fetchall()

        # 3. Filtered Incidents Query
        conditions = []
        params = []

        q = filters.get("q", "").strip()
        if q:
            like_term = f"%{q}%"
            conditions.append("""
                (
                    CAST(incident_id AS CHAR) LIKE %s
                    OR title LIKE %s
                    OR attack_type LIKE %s
                    OR severity LIKE %s
                    OR status LIKE %s
                    OR COALESCE(assigned_analyst, '') LIKE %s
                    OR COALESCE(investigation_status, '') LIKE %s
                    OR COALESCE(conclusion, '') LIKE %s
                )
            """)
            params.extend([like_term] * 8)

        if filters.get("severity_filter"):
            conditions.append("severity = %s")
            params.append(filters["severity_filter"])

        if filters.get("status_filter"):
            conditions.append("status = %s")
            params.append(filters["status_filter"])

        if filters.get("attack_type_filter"):
            conditions.append("attack_type = %s")
            params.append(filters["attack_type_filter"])

        where_clause = ""
        if conditions:
            where_clause = "WHERE " + " AND ".join(conditions)

        query = f"""
            SELECT
                incident_id,
                title,
                attack_type,
                severity,
                status,
                detected_at,
                resolved_at,
                assigned_analyst,
                investigation_status,
                conclusion
            FROM v_incident_overview
            {where_clause}
            ORDER BY detected_at DESC, incident_id DESC
        """
        cursor.execute(query, tuple(params))
        incidents = cursor.fetchall()

        return stats, incidents, attack_types
    finally:
        connection.close()


def get_analytics_data() -> Dict[str, Any]:
    """
    Query MySQL database to build Chart.js datasets for:
    - Severity Distribution
    - Status Distribution
    - Attack Vectors Distribution
    - Analyst Workload Statistics (In Progress vs Completed)
    """
    connection = get_db()
    try:
        cursor = connection.cursor(dictionary=True)

        # Severity breakdown
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        severity_counts = {sev: 0 for sev in severity_order}
        cursor.execute("SELECT severity, COUNT(*) AS total FROM incidents GROUP BY severity")
        for row in cursor.fetchall():
            if row["severity"] in severity_counts:
                severity_counts[row["severity"]] = int(row["total"])

        # Status breakdown
        status_order = ["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"]
        status_counts = {st: 0 for st in status_order}
        cursor.execute("SELECT status, COUNT(*) AS total FROM incidents GROUP BY status")
        for row in cursor.fetchall():
            if row["status"] in status_counts:
                status_counts[row["status"]] = int(row["total"])

        # Attack types breakdown
        cursor.execute("""
            SELECT a.type_name, COUNT(i.incident_id) AS total
            FROM attack_types a
            LEFT JOIN incidents i ON i.attack_type_id = a.attack_type_id
            GROUP BY a.attack_type_id, a.type_name
            ORDER BY total DESC, a.type_name ASC
        """)
        attack_type_rows = cursor.fetchall()

        # Analyst workload breakdown (active vs completed)
        cursor.execute("""
            SELECT
                a.full_name,
                COALESCE(SUM(inv.status = 'IN_PROGRESS'), 0) AS count_in_progress,
                COALESCE(SUM(inv.status = 'COMPLETED'), 0) AS count_completed,
                COUNT(inv.investigation_id) AS total_assigned
            FROM analysts a
            LEFT JOIN investigations inv ON a.analyst_id = inv.analyst_id
            GROUP BY a.analyst_id, a.full_name
            ORDER BY a.full_name ASC
        """)
        analyst_workload_rows = cursor.fetchall()

        return {
            "severity_labels": severity_order,
            "severity_values": [severity_counts[s] for s in severity_order],
            "status_labels": status_order,
            "status_values": [status_counts[s] for s in status_order],
            "attack_type_labels": [r["type_name"] for r in attack_type_rows],
            "attack_type_values": [int(r["total"]) for r in attack_type_rows],
            "analyst_labels": [r["full_name"] for r in analyst_workload_rows],
            "analyst_in_progress": [int(r["count_in_progress"]) for r in analyst_workload_rows],
            "analyst_completed": [int(r["count_completed"]) for r in analyst_workload_rows],
        }
    finally:
        connection.close()


# -----------------------------------------------------------------------------
# Liveness & Health Check Endpoint (Render / Load Balancers)
# -----------------------------------------------------------------------------

@app.route("/health", methods=["GET"])
def health():
    """Production-safe liveness health-check endpoint for Render.

    Returns HTTP 200 without requiring database connectivity or authentication.
    """
    return jsonify({"status": "healthy", "service": "CyberShield"}), 200


# -----------------------------------------------------------------------------
# Module 0: Authentication & Access Control Routes
# -----------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    """Display authentication page or verify user credentials."""
    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    next_url = request.args.get("next") or request.form.get("next")

    if request.method == "POST":
        client_ip = request.remote_addr or "127.0.0.1"

        # 1. Rate limiting & Brute force protection check
        if is_rate_limited(client_ip):
            flash("Too many failed login attempts. Access temporarily locked for 5 minutes. Please try again later.", "error")
            return render_template("login.html", prev_login="", next_url=next_url), 429

        identifier = request.form.get("login_identifier", "").strip()
        password = request.form.get("password", "")
        remember_me = bool(request.form.get("remember_me"))

        if not identifier or not password:
            flash("Please enter both username or email and password.", "error")
            return render_template("login.html", prev_login=identifier, next_url=next_url), 400

        user = get_user_by_identifier(identifier)

        # 2. Check credentials (generic error to prevent account enumeration)
        if not user or not check_password_hash(user["password_hash"], password):
            record_failed_attempt(client_ip)
            app.logger.warning("Failed login attempt for identifier: %s from IP: %s", identifier, client_ip)
            flash("Invalid username/email or password.", "error")
            return render_template("login.html", prev_login=identifier, next_url=next_url), 401

        # 3. Check account status
        if user["account_status"] != "ACTIVE":
            record_failed_attempt(client_ip)
            app.logger.warning("Login rejected for disabled account: %s", identifier)
            flash("Account is disabled. Please contact your system administrator.", "error")
            return render_template("login.html", prev_login=identifier, next_url=next_url), 403

        # 4. Successful authentication - Clear brute force tracker
        clear_failed_attempts(client_ip)

        # 5. Session Fixation Protection: Clear existing session and re-seed CSRF token
        session.clear()
        session["user_id"] = user["user_id"]
        session["username"] = user["username"]
        session["full_name"] = user["full_name"]
        session["email"] = user["email"]
        session["role"] = user["role_name"]
        session["_csrf_token"] = secrets.token_hex(32)

        if remember_me:
            session.permanent = True
        else:
            session.permanent = False

        # 6. Update last_login timestamp in database
        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET last_login = NOW() WHERE user_id = %s", (user["user_id"],))
            conn.commit()
            conn.close()
        except Exception as e:
            app.logger.error("Failed to record last_login timestamp: %s", e)

        flash(f"Welcome back, {user['full_name']}! Signed in as {user['role_name']}.", "success")

        # 7. Safe redirection to next_url
        if next_url and is_safe_url(next_url):
            return redirect(next_url)
        return redirect(url_for("dashboard"))

    return render_template("login.html", next_url=next_url)


@app.route("/logout", methods=["POST", "GET"])
def logout():
    """Sign out the current user, clear session tokens, and redirect to login."""
    session.clear()
    flash("You have been signed out successfully.", "success")
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register_user():
    """
    User registration endpoint:
    - If unauthenticated: Public self-registration (allows new users to sign up as ANALYST or VIEWER).
    - If authenticated as ADMIN: Administrative console to provision users with any role & manage accounts.
    - If authenticated as non-admin: Redirects to dashboard (already registered).
    """
    user_id = session.get("user_id")
    user_role = session.get("role")

    # 1. Non-admin authenticated users cannot access administrative user registration
    if user_id and user_role != "ADMIN":
        app.logger.warning("Access denied for user '%s' (role: %s) to /register", session.get("username"), user_role)
        flash(f"Access denied: '{user_role}' role lacks permission for user registration.", "error")
        abort(403)

    # 2. Administrator console flow
    if user_id and user_role == "ADMIN":
        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT role_id, role_name, description FROM roles ORDER BY role_id ASC")
        roles = cursor.fetchall()

        cursor.execute("""
            SELECT u.user_id, u.full_name, u.username, u.email, u.role_id,
                   u.account_status, u.created_at, u.last_login, r.role_name
            FROM users u
            JOIN roles r ON u.role_id = r.role_id
            ORDER BY u.created_at DESC
        """)
        existing_users = cursor.fetchall()
        conn.close()

        if request.method == "POST":
            full_name = request.form.get("full_name", "").strip()
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            role_id_raw = request.form.get("role_id", "").strip()
            account_status = request.form.get("account_status", "ACTIVE").strip().upper()

            if not full_name or not username or not email or not password or not role_id_raw:
                flash("All fields are required to register an account.", "error")
                return render_template("register.html", roles=roles, existing_users=existing_users), 400

            if len(password) < 8:
                flash("Password must be at least 8 characters long.", "error")
                return render_template("register.html", roles=roles, existing_users=existing_users), 400

            try:
                role_id = int(role_id_raw)
            except ValueError:
                flash("Invalid role selected.", "error")
                return render_template("register.html", roles=roles, existing_users=existing_users), 400

            conn = get_db()
            try:
                cursor = conn.cursor(dictionary=True)
                cursor.execute("SELECT user_id, username, email FROM users WHERE username = %s OR email = %s LIMIT 1", (username, email))
                existing = cursor.fetchone()
                if existing:
                    if existing["username"].lower() == username.lower():
                        flash(f"Account with username '{username}' already exists.", "error")
                    else:
                        flash(f"Account with email '{email}' already exists.", "error")
                    return render_template("register.html", roles=roles, existing_users=existing_users), 400

                hashed = generate_password_hash(password)
                cursor.execute("""
                    INSERT INTO users (full_name, username, email, password_hash, role_id, account_status, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, NOW())
                """, (full_name, username, email, hashed, role_id, account_status))
                conn.commit()
                flash(f"Account '{username}' successfully registered.", "success")
                return redirect(url_for("register_user"))
            finally:
                conn.close()

        return render_template("register.html", roles=roles, existing_users=existing_users)

    # 3. Public self-registration flow (for unauthenticated visitors)
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        role_id_raw = request.form.get("role_id", "2").strip()

        # Validate role: only ANALYST (2) or VIEWER (3) allowed for self-registration
        try:
            role_id = int(role_id_raw)
            if role_id not in (2, 3):
                role_id = 2
        except (ValueError, TypeError):
            role_id = 2

        if not full_name or not username or not email or not password or not confirm_password:
            flash("All fields are required to create an account.", "error")
            return render_template("public_register.html", prev_full_name=full_name, prev_username=username, prev_email=email, prev_role=str(role_id)), 400

        if len(username) < 3 or len(username) > 50:
            flash("Username must be between 3 and 50 characters long.", "error")
            return render_template("public_register.html", prev_full_name=full_name, prev_username=username, prev_email=email, prev_role=str(role_id)), 400

        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "error")
            return render_template("public_register.html", prev_full_name=full_name, prev_username=username, prev_email=email, prev_role=str(role_id)), 400

        if password != confirm_password:
            flash("Passwords do not match. Please verify both password entries.", "error")
            return render_template("public_register.html", prev_full_name=full_name, prev_username=username, prev_email=email, prev_role=str(role_id)), 400

        conn = get_db()
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT user_id, username, email FROM users WHERE username = %s OR email = %s LIMIT 1", (username, email))
            existing = cursor.fetchone()
            if existing:
                if existing["username"].lower() == username.lower():
                    flash(f"Username '{username}' is already taken. Please choose a different username.", "error")
                else:
                    flash(f"Email '{email}' is already registered. Please sign in instead.", "error")
                return render_template("public_register.html", prev_full_name=full_name, prev_username=username, prev_email=email, prev_role=str(role_id)), 400

            hashed = generate_password_hash(password)
            cursor.execute("""
                INSERT INTO users (full_name, username, email, password_hash, role_id, account_status, created_at, last_login)
                VALUES (%s, %s, %s, %s, %s, 'ACTIVE', NOW(), NOW())
            """, (full_name, username, email, hashed, role_id))
            conn.commit()
            new_user_id = cursor.lastrowid

            # Fetch created role name
            cursor.execute("SELECT role_name FROM roles WHERE role_id = %s", (role_id,))
            role_row = cursor.fetchone()
            role_name = role_row["role_name"] if role_row else "ANALYST"

            # Auto-authenticate user into a fresh session with fixation protection
            session.clear()
            session["user_id"] = new_user_id
            session["username"] = username
            session["full_name"] = full_name
            session["email"] = email
            session["role"] = role_name
            session["_csrf_token"] = secrets.token_hex(32)

            flash(f"Welcome to CyberShield, {full_name}! Your account has been registered successfully as {role_name}.", "success")
            return redirect(url_for("dashboard"))
        finally:
            conn.close()

    return render_template("public_register.html")


@app.cli.command("create-admin")
@click.option("--full-name", prompt="Full Name", help="Admin's full name")
@click.option("--username", prompt="Username", help="Unique username")
@click.option("--email", prompt="Email Address", help="Unique email address")
@click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True, help="Secure password")
def create_admin_cli(full_name, username, email, password):
    """Flask CLI command to provision the initial administrator account."""
    from create_admin import create_admin_account
    if create_admin_account(full_name, username, email, password):
        click.echo("[SUCCESS] Admin created successfully.")
    else:
        click.echo("[FAILED] Could not create admin account.")


# -----------------------------------------------------------------------------
# Module A: Dashboard Route
# -----------------------------------------------------------------------------

@app.route("/")
@login_required
def dashboard():
    """Main executive dashboard featuring KPIs, interactive charts, and filtered incidents."""
    q = request.args.get("q", "").strip()[:100]
    severity_filter = request.args.get("severity_filter", "").strip().upper()
    status_filter = request.args.get("status_filter", "").strip().upper()
    attack_type_filter = request.args.get("attack_type_filter", "").strip()

    if severity_filter not in VALID_SEVERITIES:
        severity_filter = ""
    if status_filter not in VALID_STATUSES:
        status_filter = ""

    filters = {
        "q": q,
        "severity_filter": severity_filter,
        "status_filter": status_filter,
        "attack_type_filter": attack_type_filter,
    }

    try:
        stats, incidents, attack_types = get_dashboard_data(filters)

        valid_attack_type_names = {at["type_name"] for at in attack_types}
        if attack_type_filter and attack_type_filter not in valid_attack_type_names:
            filters["attack_type_filter"] = ""
            stats, incidents, attack_types = get_dashboard_data(filters)

        analytics = get_analytics_data()

        return render_template(
            "index.html",
            stats=stats,
            incidents=incidents,
            attack_types=attack_types,
            filters=filters,
            status_transitions=STATUS_TRANSITIONS,
            analytics=analytics,
        )

    except mysql.connector.Error:
        app.logger.exception("Failed to load dashboard data from MySQL")
        return (
            "Could not connect to CyberShield database. Ensure MySQL is running and configured correctly.",
            500,
        )


# -----------------------------------------------------------------------------
# Module B: Incident Management Routes
# -----------------------------------------------------------------------------

@app.route("/incidents/new", methods=["GET", "POST"])
@login_required
@role_required("ADMIN", "ANALYST")
def add_incident():
    """Register a new cybersecurity incident with validation and optional linkages."""
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        attack_type_id_raw = request.form.get("attack_type_id", "").strip()
        severity = request.form.get("severity", "").strip().upper()
        analyst_id_raw = request.form.get("analyst_id", "").strip()
        device_id_raw = request.form.get("device_id", "").strip()

        # Server-side validation
        if not title or len(title) > 200:
            flash("Incident title is required and must be 200 characters or fewer.", "error")
            return redirect(url_for("add_incident"))

        if len(description) > 5000:
            flash("Description must be 5000 characters or fewer.", "error")
            return redirect(url_for("add_incident"))

        if severity not in VALID_SEVERITIES:
            flash("Select a valid severity tier.", "error")
            return redirect(url_for("add_incident"))

        try:
            attack_type_id = int(attack_type_id_raw)
        except ValueError:
            flash("Invalid attack type selected.", "error")
            return redirect(url_for("add_incident"))

        connection = None
        try:
            connection = get_db()
            cursor = connection.cursor(dictionary=True)

            cursor.execute("SELECT 1 FROM attack_types WHERE attack_type_id = %s", (attack_type_id,))
            if cursor.fetchone() is None:
                flash("Selected attack vector does not exist in database.", "error")
                return redirect(url_for("add_incident"))

            # Insert incident (defaults to OPEN status)
            cursor.execute("""
                INSERT INTO incidents (title, description, attack_type_id, severity, status)
                VALUES (%s, %s, %s, %s, 'OPEN')
            """, (title, description or None, attack_type_id, severity))
            incident_id = cursor.lastrowid

            # Optional: Initial Analyst Assignment
            if analyst_id_raw:
                try:
                    analyst_id = int(analyst_id_raw)
                    cursor.execute("SELECT 1 FROM analysts WHERE analyst_id = %s", (analyst_id,))
                    if cursor.fetchone():
                        cursor.execute("""
                            INSERT INTO investigations (incident_id, analyst_id, status)
                            VALUES (%s, %s, 'ASSIGNED')
                        """, (incident_id, analyst_id))
                except ValueError:
                    pass

            # Optional: Initial Device Linkage
            if device_id_raw:
                try:
                    device_id = int(device_id_raw)
                    cursor.execute("SELECT 1 FROM devices WHERE device_id = %s", (device_id,))
                    if cursor.fetchone():
                        cursor.execute("""
                            INSERT INTO incident_devices (incident_id, device_id, impact_description)
                            VALUES (%s, %s, %s)
                        """, (incident_id, device_id, "Linked during incident creation"))
                except ValueError:
                    pass

            connection.commit()
            flash(f"Incident #{incident_id} successfully registered into CyberShield.", "success")
            return redirect(url_for("incident_detail", incident_id=incident_id))

        except mysql.connector.Error:
            if connection:
                connection.rollback()
            app.logger.exception("Failed to insert new incident")
            flash("Database error occurred while recording the incident.", "error")
            return redirect(url_for("add_incident"))
        finally:
            if connection and connection.is_connected():
                connection.close()

    # GET Request: Prepare form options
    connection = None
    try:
        connection = get_db()
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT attack_type_id, type_name FROM attack_types ORDER BY type_name ASC")
        attack_types = cursor.fetchall()

        cursor.execute("SELECT analyst_id, full_name, role FROM analysts ORDER BY full_name ASC")
        analysts = cursor.fetchall()

        cursor.execute("SELECT device_id, hostname, device_type, department FROM devices ORDER BY hostname ASC")
        devices = cursor.fetchall()

        return render_template(
            "add_incident.html",
            attack_types=attack_types,
            analysts=analysts,
            devices=devices,
        )
    finally:
        if connection and connection.is_connected():
            connection.close()


@app.route("/incidents/<int:incident_id>")
@login_required
def incident_detail(incident_id: int):
    """View full incident telemetry, analyst investigation, impacted infrastructure, and audit timeline."""
    connection = None
    try:
        connection = get_db()
        cursor = connection.cursor(dictionary=True)

        # 1. Incident details with attack type and analyst info
        cursor.execute("""
            SELECT
                i.incident_id,
                i.title,
                i.description,
                i.attack_type_id,
                a.type_name AS attack_type,
                i.severity,
                i.status,
                i.detected_at,
                i.resolved_at,
                inv.investigation_id,
                inv.analyst_id,
                inv.status AS investigation_status,
                inv.started_at AS investigation_started_at,
                inv.conclusion,
                an.full_name AS analyst_name,
                an.email AS analyst_email,
                an.role AS analyst_role
            FROM incidents i
            JOIN attack_types a ON i.attack_type_id = a.attack_type_id
            LEFT JOIN investigations inv ON i.incident_id = inv.incident_id
            LEFT JOIN analysts an ON inv.analyst_id = an.analyst_id
            WHERE i.incident_id = %s
        """, (incident_id,))
        incident = cursor.fetchone()

        if incident is None:
            flash(f"Incident #{incident_id} not found.", "error")
            return redirect(url_for("dashboard"))

        # 2. Associated Devices
        cursor.execute("""
            SELECT
                d.device_id,
                d.hostname,
                d.device_type,
                d.operating_system,
                d.department,
                d.criticality,
                id.impact_description
            FROM incident_devices id
            JOIN devices d ON id.device_id = d.device_id
            WHERE id.incident_id = %s
            ORDER BY d.hostname ASC
        """, (incident_id,))
        devices = cursor.fetchall()

        # 3. Associated IP Addresses
        cursor.execute("""
            SELECT
                ip.ip_id,
                ip.ip_address,
                ip.reputation,
                ii.association_type
            FROM incident_ips ii
            JOIN ip_addresses ip ON ii.ip_id = ip.ip_id
            WHERE ii.incident_id = %s
            ORDER BY ip.ip_address ASC
        """, (incident_id,))
        ip_addresses = cursor.fetchall()

        # 4. Status History Timeline for this incident
        cursor.execute("""
            SELECT
                history_id,
                old_status,
                new_status,
                changed_at,
                changed_by
            FROM incident_status_history
            WHERE incident_id = %s
            ORDER BY changed_at ASC, history_id ASC
        """, (incident_id,))
        history = cursor.fetchall()

        # 5. Helper lists for assignment & link forms
        cursor.execute("SELECT analyst_id, full_name, role FROM analysts ORDER BY full_name ASC")
        analysts = cursor.fetchall()

        cursor.execute("SELECT device_id, hostname, device_type, department FROM devices ORDER BY hostname ASC")
        all_devices = cursor.fetchall()

        cursor.execute("SELECT ip_id, ip_address, reputation FROM ip_addresses ORDER BY ip_address ASC")
        all_ips = cursor.fetchall()

        return render_template(
            "incident_detail.html",
            incident=incident,
            devices=devices,
            ip_addresses=ip_addresses,
            history=history,
            analysts=analysts,
            all_devices=all_devices,
            all_ips=all_ips,
            status_transitions=STATUS_TRANSITIONS,
        )

    except mysql.connector.Error:
        app.logger.exception("Failed to load incident detail for #%s", incident_id)
        flash("Could not retrieve incident details from MySQL.", "error")
        return redirect(url_for("dashboard"))
    finally:
        if connection and connection.is_connected():
            connection.close()


@app.route("/incidents/<int:incident_id>/edit", methods=["GET", "POST"])
@login_required
@role_required("ADMIN", "ANALYST")
def edit_incident(incident_id: int):
    """Edit incident metadata (title, description, attack type, severity)."""
    connection = None
    try:
        connection = get_db()
        cursor = connection.cursor(dictionary=True)

        cursor.execute("""
            SELECT incident_id, title, description, attack_type_id, severity, status
            FROM incidents
            WHERE incident_id = %s
        """, (incident_id,))
        incident = cursor.fetchone()

        if not incident:
            flash(f"Incident #{incident_id} not found.", "error")
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            title = request.form.get("title", "").strip()
            description = request.form.get("description", "").strip()
            attack_type_id_raw = request.form.get("attack_type_id", "").strip()
            severity = request.form.get("severity", "").strip().upper()

            if not title or len(title) > 200:
                flash("Title is required and must be 200 characters or fewer.", "error")
                return redirect(url_for("edit_incident", incident_id=incident_id))

            if len(description) > 5000:
                flash("Description must be 5000 characters or fewer.", "error")
                return redirect(url_for("edit_incident", incident_id=incident_id))

            if severity not in VALID_SEVERITIES:
                flash("Select a valid severity tier.", "error")
                return redirect(url_for("edit_incident", incident_id=incident_id))

            try:
                attack_type_id = int(attack_type_id_raw)
            except ValueError:
                flash("Invalid attack type selected.", "error")
                return redirect(url_for("edit_incident", incident_id=incident_id))

            cursor.execute("SELECT 1 FROM attack_types WHERE attack_type_id = %s", (attack_type_id,))
            if cursor.fetchone() is None:
                flash("Selected attack type is invalid.", "error")
                return redirect(url_for("edit_incident", incident_id=incident_id))

            cursor.execute("""
                UPDATE incidents
                SET title = %s,
                    description = %s,
                    attack_type_id = %s,
                    severity = %s
                WHERE incident_id = %s
            """, (title, description or None, attack_type_id, severity, incident_id))

            connection.commit()
            flash(f"Incident #{incident_id} updated successfully.", "success")
            return redirect(url_for("incident_detail", incident_id=incident_id))

        # GET: render edit template
        cursor.execute("SELECT attack_type_id, type_name FROM attack_types ORDER BY type_name ASC")
        attack_types = cursor.fetchall()

        return render_template(
            "edit_incident.html",
            incident=incident,
            attack_types=attack_types,
        )

    except mysql.connector.Error:
        if connection:
            connection.rollback()
        app.logger.exception("Failed to edit incident #%s", incident_id)
        flash("Database error occurred while updating incident.", "error")
        return redirect(url_for("incident_detail", incident_id=incident_id))
    finally:
        if connection and connection.is_connected():
            connection.close()


@app.route("/incidents/<int:incident_id>/status", methods=["POST"])
@login_required
@role_required("ADMIN", "ANALYST")
def update_incident_status(incident_id: int):
    """
    Validate and execute an incident status transition according to permitted workflow rules.
    Trigger trg_validate_incident_status guarantees database-level integrity,
    and trigger trg_record_incident_status records the change with @cybershield_actor.
    """
    new_status = request.form.get("status", "").strip().upper()
    next_url = request.form.get("next_url", "").strip()

    redirect_filters = {
        "q": request.form.get("q", "")[:100],
        "severity_filter": request.form.get("severity_filter", ""),
        "status_filter": request.form.get("status_filter", ""),
        "attack_type_filter": request.form.get("attack_type_filter", ""),
    }

    def get_redirect():
        if next_url and next_url.startswith("/"):
            return redirect(next_url)
        return redirect(url_for("dashboard", **redirect_filters))

    if new_status not in VALID_STATUSES:
        flash("Invalid target status specified.", "error")
        return get_redirect()

    connection = None
    try:
        connection = get_db()
        cursor = connection.cursor(dictionary=True)

        cursor.execute("SELECT status FROM incidents WHERE incident_id = %s", (incident_id,))
        incident = cursor.fetchone()

        if incident is None:
            flash(f"Incident #{incident_id} not found.", "error")
            return get_redirect()

        current_status = incident["status"]

        if new_status not in STATUS_TRANSITIONS.get(current_status, []):
            flash(
                f"Transition denied: cannot change status from {current_status} to {new_status}.",
                "error",
            )
            return get_redirect()

        # Set session actor for the MySQL audit trigger
        actor = session.get("username") or "CyberShield Console"
        cursor.execute("SET @cybershield_actor = %s", (actor,))

        # Update incident status with conditional resolved_at calculation
        cursor.execute("""
            UPDATE incidents
            SET status = %s,
                resolved_at = CASE
                    WHEN %s IN ('RESOLVED', 'CLOSED') AND resolved_at IS NULL
                    THEN CURRENT_TIMESTAMP
                    ELSE resolved_at
                END
            WHERE incident_id = %s
        """, (new_status, new_status, incident_id))

        connection.commit()
        flash(f"Incident #{incident_id} transition completed: {current_status} → {new_status}.", "success")

    except mysql.connector.Error as err:
        if connection:
            connection.rollback()
        app.logger.exception("Failed to update status for incident #%s", incident_id)
        if err.errno == 1644:  # Trigger SIGNAL SQLSTATE '45000'
            flash(f"Database constraint violation: {err.msg}", "error")
        else:
            flash("Database error during status transition. Check server logs.", "error")
    finally:
        if connection and connection.is_connected():
            connection.close()

    return get_redirect()


# -----------------------------------------------------------------------------
# Module C: Analyst Management Routes
# -----------------------------------------------------------------------------

@app.route("/analysts")
@login_required
def analysts_roster():
    """Security Analyst command center showing roster, workload stats, active cases, and unassigned queue."""
    connection = None
    try:
        connection = get_db()
        cursor = connection.cursor(dictionary=True)

        # 1. Query analysts with aggregated investigation counts
        cursor.execute("""
            SELECT
                a.analyst_id,
                a.full_name,
                a.email,
                a.role,
                COUNT(inv.investigation_id) AS total_assigned,
                COALESCE(SUM(inv.status = 'ASSIGNED'), 0) AS count_assigned,
                COALESCE(SUM(inv.status = 'IN_PROGRESS'), 0) AS count_in_progress,
                COALESCE(SUM(inv.status = 'COMPLETED'), 0) AS count_completed
            FROM analysts a
            LEFT JOIN investigations inv ON a.analyst_id = inv.analyst_id
            GROUP BY a.analyst_id, a.full_name, a.email, a.role
            ORDER BY total_assigned DESC, a.full_name ASC
        """)
        raw_analysts = cursor.fetchall()
        analysts = []
        for a in raw_analysts:
            analysts.append({
                "analyst_id": a["analyst_id"],
                "full_name": a["full_name"],
                "email": a["email"],
                "role": a["role"],
                "total_assigned": int(a["total_assigned"]),
                "count_assigned": int(a["count_assigned"]),
                "count_in_progress": int(a["count_in_progress"]),
                "count_completed": int(a["count_completed"]),
                "assigned_incidents": [],
            })

        # 2. Query incidents assigned to each analyst
        cursor.execute("""
            SELECT
                inv.analyst_id,
                i.incident_id,
                i.title,
                i.severity,
                i.status,
                a.type_name AS attack_type,
                inv.status AS investigation_status,
                inv.conclusion
            FROM investigations inv
            JOIN incidents i ON inv.incident_id = i.incident_id
            JOIN attack_types a ON i.attack_type_id = a.attack_type_id
            ORDER BY i.detected_at DESC
        """)
        assigned_cases = cursor.fetchall()

        analyst_map = {a["analyst_id"]: a for a in analysts}
        for case in assigned_cases:
            if case["analyst_id"] in analyst_map:
                analyst_map[case["analyst_id"]]["assigned_incidents"].append(case)

        # 3. Unassigned incidents needing triage
        cursor.execute("""
            SELECT
                i.incident_id,
                i.title,
                i.severity,
                i.status,
                i.detected_at,
                a.type_name AS attack_type
            FROM incidents i
            JOIN attack_types a ON i.attack_type_id = a.attack_type_id
            LEFT JOIN investigations inv ON i.incident_id = inv.incident_id
            WHERE inv.investigation_id IS NULL
            ORDER BY i.detected_at DESC
        """)
        unassigned_incidents = cursor.fetchall()

        return render_template(
            "analysts.html",
            analysts=analysts,
            unassigned_incidents=unassigned_incidents,
        )

    except mysql.connector.Error:
        app.logger.exception("Failed to load analyst roster from MySQL")
        flash("Could not retrieve security analysts from the database.", "error")
        return redirect(url_for("dashboard"))
    finally:
        if connection and connection.is_connected():
            connection.close()


@app.route("/incidents/<int:incident_id>/assign", methods=["POST"])
@login_required
@role_required("ADMIN", "ANALYST")
def assign_analyst(incident_id: int):
    """Assign or reassign an analyst to a security incident."""
    analyst_id_raw = request.form.get("analyst_id", "").strip()
    next_url = request.form.get("next_url", "").strip()

    try:
        analyst_id = int(analyst_id_raw)
    except ValueError:
        flash("Please select a valid security analyst.", "error")
        return redirect(request.referrer or url_for("incident_detail", incident_id=incident_id))

    connection = None
    try:
        connection = get_db()
        cursor = connection.cursor(dictionary=True)

        cursor.execute("SELECT 1 FROM incidents WHERE incident_id = %s", (incident_id,))
        if not cursor.fetchone():
            flash(f"Incident #{incident_id} not found.", "error")
            return redirect(url_for("dashboard"))

        cursor.execute("SELECT full_name FROM analysts WHERE analyst_id = %s", (analyst_id,))
        analyst = cursor.fetchone()
        if not analyst:
            flash("Selected security analyst was not found.", "error")
            return redirect(request.referrer or url_for("incident_detail", incident_id=incident_id))

        # Check if an investigation record already exists
        cursor.execute("SELECT investigation_id, status FROM investigations WHERE incident_id = %s", (incident_id,))
        existing_inv = cursor.fetchone()

        if existing_inv:
            cursor.execute("""
                UPDATE investigations
                SET analyst_id = %s
                WHERE incident_id = %s
            """, (analyst_id, incident_id))
            action_desc = "reassigned"
        else:
            cursor.execute("""
                INSERT INTO investigations (incident_id, analyst_id, status)
                VALUES (%s, %s, 'ASSIGNED')
            """, (incident_id, analyst_id))
            action_desc = "assigned"

        connection.commit()
        flash(f"Analyst {analyst['full_name']} {action_desc} to Incident #{incident_id}.", "success")

    except mysql.connector.Error:
        if connection:
            connection.rollback()
        app.logger.exception("Failed to assign analyst to incident #%s", incident_id)
        flash("Could not update analyst assignment due to a database error.", "error")
    finally:
        if connection and connection.is_connected():
            connection.close()

    if next_url and next_url.startswith("/"):
        return redirect(next_url)
    return redirect(request.referrer or url_for("incident_detail", incident_id=incident_id))


@app.route("/incidents/<int:incident_id>/investigation", methods=["POST"])
@login_required
@role_required("ADMIN", "ANALYST")
def update_investigation(incident_id: int):
    """Update investigation status and record forensic conclusions."""
    new_status = request.form.get("status", "").strip().upper()
    conclusion = request.form.get("conclusion", "").strip()

    if new_status not in VALID_INVESTIGATION_STATUSES:
        flash("Invalid investigation status tier.", "error")
        return redirect(url_for("incident_detail", incident_id=incident_id))

    connection = None
    try:
        connection = get_db()
        cursor = connection.cursor(dictionary=True)

        cursor.execute("SELECT investigation_id FROM investigations WHERE incident_id = %s", (incident_id,))
        if not cursor.fetchone():
            flash("No investigation record exists for this incident. Assign an analyst first.", "error")
            return redirect(url_for("incident_detail", incident_id=incident_id))

        cursor.execute("""
            UPDATE investigations
            SET status = %s,
                conclusion = %s
            WHERE incident_id = %s
        """, (new_status, conclusion or None, incident_id))

        connection.commit()
        flash(f"Investigation notes and status updated for Incident #{incident_id}.", "success")

    except mysql.connector.Error:
        if connection:
            connection.rollback()
        app.logger.exception("Failed to update investigation for incident #%s", incident_id)
        flash("Database error while updating investigation progress.", "error")
    finally:
        if connection and connection.is_connected():
            connection.close()

    return redirect(url_for("incident_detail", incident_id=incident_id))


@app.route("/incidents/<int:incident_id>/devices", methods=["POST"])
@login_required
@role_required("ADMIN", "ANALYST")
def link_incident_device(incident_id: int):
    """Attach an impacted endpoint to the incident."""
    device_id_raw = request.form.get("device_id", "").strip()
    impact_desc = request.form.get("impact_description", "").strip()

    try:
        device_id = int(device_id_raw)
    except ValueError:
        flash("Invalid device selected.", "error")
        return redirect(url_for("incident_detail", incident_id=incident_id))

    connection = None
    try:
        connection = get_db()
        cursor = connection.cursor()

        cursor.execute("""
            INSERT INTO incident_devices (incident_id, device_id, impact_description)
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE impact_description = VALUES(impact_description)
        """, (incident_id, device_id, impact_desc or "Impacted endpoint linked"))

        connection.commit()
        flash(f"Device successfully linked to Incident #{incident_id}.", "success")

    except mysql.connector.Error:
        if connection:
            connection.rollback()
        app.logger.exception("Failed to link device to incident #%s", incident_id)
        flash("Could not attach device to incident.", "error")
    finally:
        if connection and connection.is_connected():
            connection.close()

    return redirect(url_for("incident_detail", incident_id=incident_id))


@app.route("/incidents/<int:incident_id>/ips", methods=["POST"])
@login_required
@role_required("ADMIN", "ANALYST")
def link_incident_ip(incident_id: int):
    """Attach an associated IP address indicator to the incident."""
    ip_id_raw = request.form.get("ip_id", "").strip()
    assoc_type = request.form.get("association_type", "RELATED").strip().upper()

    if assoc_type not in {"SOURCE", "DESTINATION", "RELATED"}:
        assoc_type = "RELATED"

    try:
        ip_id = int(ip_id_raw)
    except ValueError:
        flash("Invalid IP address indicator selected.", "error")
        return redirect(url_for("incident_detail", incident_id=incident_id))

    connection = None
    try:
        connection = get_db()
        cursor = connection.cursor()

        cursor.execute("""
            INSERT INTO incident_ips (incident_id, ip_id, association_type)
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE association_type = VALUES(association_type)
        """, (incident_id, ip_id, assoc_type))

        connection.commit()
        flash(f"IP address indicator linked to Incident #{incident_id}.", "success")

    except mysql.connector.Error:
        if connection:
            connection.rollback()
        app.logger.exception("Failed to link IP to incident #%s", incident_id)
        flash("Could not attach IP indicator to incident.", "error")
    finally:
        if connection and connection.is_connected():
            connection.close()

    return redirect(url_for("incident_detail", incident_id=incident_id))


# -----------------------------------------------------------------------------
# Module D: Audit History Route
# -----------------------------------------------------------------------------

@app.route("/audit")
@login_required
def audit_history():
    """Display immutable chronological incident status transitions recorded by MySQL triggers."""
    q = request.args.get("q", "").strip()[:100]
    status_filter = request.args.get("status_filter", "").strip().upper()

    if status_filter not in VALID_STATUSES:
        status_filter = ""

    conditions = []
    params = []

    if q:
        like_term = f"%{q}%"
        conditions.append("""
            (
                CAST(h.incident_id AS CHAR) LIKE %s
                OR i.title LIKE %s
                OR h.changed_by LIKE %s
            )
        """)
        params.extend([like_term, like_term, like_term])

    if status_filter:
        conditions.append("(h.old_status = %s OR h.new_status = %s)")
        params.extend([status_filter, status_filter])

    where_clause = ""
    if conditions:
        where_clause = "WHERE " + " AND ".join(conditions)

    connection = None
    try:
        connection = get_db()
        cursor = connection.cursor(dictionary=True)

        query = f"""
            SELECT
                h.history_id,
                h.incident_id,
                i.title AS incident_title,
                h.old_status,
                h.new_status,
                h.changed_at,
                h.changed_by
            FROM incident_status_history h
            JOIN incidents i ON i.incident_id = h.incident_id
            {where_clause}
            ORDER BY h.changed_at DESC, h.history_id DESC
            LIMIT 500
        """
        cursor.execute(query, tuple(params))
        history = cursor.fetchall()

        cursor.execute("SELECT COUNT(*) AS total FROM incident_status_history")
        total_history = cursor.fetchone()["total"]

        return render_template(
            "audit.html",
            history=history,
            total_history=total_history,
            q=q,
            status_filter=status_filter,
            valid_statuses=sorted(VALID_STATUSES),
        )

    except mysql.connector.Error:
        app.logger.exception("Failed to query audit history from MySQL")
        return "Could not load audit history. Ensure MySQL server and required tables are available.", 500
    finally:
        if connection and connection.is_connected():
            connection.close()


# -----------------------------------------------------------------------------
# Entry Point
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    debug_mode = os.getenv("FLASK_DEBUG", "True").lower() in ("true", "1", "yes")
    app.run(host="0.0.0.0", port=5000, debug=debug_mode)
