# CyberShield — Cybersecurity Incident Intelligence System

CyberShield is an enterprise-grade, centralized security incident operations platform. Built for Security Operations Center (SOC) teams, incident responders, and security engineers, CyberShield enables security teams to record, monitor, investigate, and analyze cybersecurity threats in real-time with relational data integrity and immutable audit provenance.

---

## 1. Project Overview

Modern security teams require an agile, structured intelligence console to manage rapid-fire security alerts. CyberShield bridges the gap between raw detection telemetry and collaborative SOC incident response by providing:

- A centralized incident register categorizing threats by attack vector and severity tier.
- A strictly enforced status transition state machine that prevents invalid operational status leaps.
- Analyst assignment, reassignment, and forensic conclusion tracking.
- Relational mapping of impacted hardware endpoints and associated network IP indicators (source, destination, C2).
- An automated audit history ledger powered by native MySQL triggers that capture every state change with actor attribution.
- An executive operations dashboard featuring real-time KPI metrics and interactive Chart.js analytics.
- A minimalist, luxurious, high-contrast dark operations interface.

---

## 2. Key Features

### Module A: Executive Dashboard & Analytics
- **Live Incident Counters**: Immediate visibility into Total, Open, Under Investigation, Contained, Resolved, Closed, and Critical/High priority incidents.
- **Severity Profile**: Live interactive doughnut chart rendering distribution across `CRITICAL`, `HIGH`, `MEDIUM`, and `LOW`.
- **Workflow State Distribution**: Real-time breakdown across `OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, and `CLOSED`.
- **Attack Vector Frequency**: Comparative bar chart evaluating threat vectors (Brute Force, Phishing, Malware, Data Exfiltration, Unauthorized Access, etc.).
- **Analyst Workload Velocity**: Grouped stacked chart comparing active investigations against completed investigations per SOC analyst.

### Module B: Incident Management
- **Incident Registration**: Record new security events with server-side validation, severity tiering, attack vector classification, and optional immediate device/analyst attachment.
- **Incident Intelligence Dossier (`/incidents/<id>`)**: Comprehensive view containing incident synopsis, affected infrastructure, associated IP indicators, lead analyst, and status transition timeline.
- **Incident Editing**: Update title, description, attack type, or severity safely.
- **State Machine Transitions**: Validated status flow (`OPEN` → `INVESTIGATING` → `CONTAINED` / `RESOLVED` → `CLOSED`), guarded in both Python application logic and MySQL triggers.

### Module C: Analyst Command & SOC Workload
- **Analyst Roster (`/analysts`)**: Monitor analyst capacity, caseloads in progress, and closed investigations.
- **Caseload Inspection**: View all active and historical incidents assigned to each analyst.
- **Unassigned Triage Queue**: Highlight unassigned security alerts requiring immediate lead analyst assignment.
- **Assignment & Reassignment**: Assign or reassign incident owners dynamically.
- **Forensic Conclusions**: Record mitigation steps, containment procedures, and root-cause summaries.

### Module D: Immutable Audit Trail (`/audit`)
- **Native Trigger-Based Auditing**: Database trigger `trg_record_incident_status` automatically captures old status, new status, timestamp, and session actor (`@cybershield_actor`).
- **Search & Filtering**: Search audit logs by incident ID, title, or actor authority, and filter by status involved.

### Module E: Security & Data Integrity
- **Parameterized SQL Queries**: All database interactions use parameterized queries (`%s`), completely mitigating SQL injection vectors.
- **Session-Based CSRF Protection**: Zero-dependency cryptographically secure token validation (`secrets.token_hex(32)`) for all state-modifying requests (`POST`).
- **Security Headers**: Standard defense-in-depth headers (`X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `X-XSS-Protection: 1; mode=block`).
- **Secure Cookie Flags**: Session cookies configured with `HttpOnly` and `SameSite=Lax`.

---

## 3. Technology Stack

- **Backend**: Python 3.10+ / Flask 3.1
- **Database**: MySQL 8.0+ (relational schema, views, triggers, foreign keys)
- **Database Driver**: `mysql-connector-python`
- **Frontend**: HTML5, CSS3, Bootstrap 5.3.3, Chart.js 4.4
- **Configuration**: Python Dotenv (`.env`)
- **Testing**: Python `unittest` test suite

---

## 4. Project Folder Structure

```
SQL_PROJECT/
│
├── app.py                      # Core Flask application, routes, and business logic
├── test_app.py                 # Comprehensive automated test suite (13 test cases)
├── .env                        # Local database credentials and app secrets (git-ignored)
├── .env.example                # Template for environment configuration
├── .gitignore                  # Git ignore rules (.env, venv/, __pycache__/)
├── README.md                   # Project documentation
│
├── database/
│   └── cybershield_schema.sql  # Complete schema, triggers, views, and initial seed data
│
├── static/
│   └── css/
│       └── cybershield.css     # Minimalist luxury dark theme stylesheet
│
└── templates/
    ├── base.html               # Shared layout, luxury top nav, footer, scripts
    ├── index.html              # Executive dashboard, hero, charts, incident directory
    ├── incident_detail.html    # Full incident dossier, infrastructure, analyst command
    ├── add_incident.html       # Incident registration form
    ├── edit_incident.html      # Incident metadata modification form
    ├── analysts.html           # SOC Analyst command center, caseloads, triage queue
    └── audit.html              # Immutable status transition audit ledger
```

---

## 5. Prerequisites

Before running the application, ensure you have:

1. **Python**: Python 3.10 or higher installed.
2. **MySQL Server**: MySQL 8.0 or higher running locally or on a remote host.
3. **Pip & Virtualenv**: Virtual environment tools.

---

## 6. MySQL Database Setup

1. Open your MySQL client (MySQL Workbench, MySQL Shell, or command line):
   ```bash
   mysql -u root -p
   ```

2. Run the provided SQL script located at `database/cybershield_schema.sql`:
   ```sql
   SOURCE database/cybershield_schema.sql;
   ```
   Or from terminal / PowerShell:
   ```bash
   mysql -u root -p < database/cybershield_schema.sql
   ```

3. Verify tables and triggers:
   ```sql
   USE cybershield;
   SHOW TABLES;
   SHOW TRIGGERS;
   ```

---

## 7. Environment Variable Configuration

Create a `.env` file in the root directory (or copy from `.env.example`):

```bash
cp .env.example .env
```

Configure the following variables:

| Variable | Description | Default / Example |
|---|---|---|
| `DB_HOST` | MySQL hostname or IP address | `localhost` |
| `DB_PORT` | MySQL connection port | `3306` |
| `DB_NAME` | MySQL database name | `cybershield` |
| `DB_USER` | MySQL user account | `root` |
| `DB_PASSWORD` | MySQL user password | `your_mysql_password` |
| `SECRET_KEY` | Secret key for session cookies and CSRF tokens | `a-strong-random-secret-key` |
| `FLASK_DEBUG` | Enable/disable Flask debug mode | `False` |

---

## 8. Installation & Running the Application

### 1. Create and Activate Virtual Environment
```bash
# Windows (PowerShell)
python -m venv venv
.\venv\Scripts\Activate.ps1

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### 2. Install Dependencies
```bash
pip install flask mysql-connector-python python-dotenv
```

### 3. Run Automated Tests
```bash
python -m unittest test_app.py
```
*Expected output: All 13 tests passing successfully with automatic cleanup.*

### 4. Start the Flask Server
```bash
python app.py
```
The application will launch on:
```
http://127.0.0.1:5000
```

---

## 9. Permitted Status Transition Rules

CyberShield enforces strict incident response state progression:

```
[ OPEN ]
   │
   ▼
[ INVESTIGATING ] ──► [ CONTAINED ]
   │                      │
   ▼                      ▼
[ RESOLVED ] ◄────────────┘
   │
   ▼
[ CLOSED ] (Terminal State)
```

- `OPEN` can only transition to `INVESTIGATING`.
- `INVESTIGATING` can transition to `CONTAINED` or `RESOLVED`.
- `CONTAINED` can transition back to `INVESTIGATING` or forward to `RESOLVED`.
- `RESOLVED` can transition to `CLOSED`.
- `CLOSED` is a terminal state with no further transitions.
- *Any unauthorized transition attempt is rejected at both the application level and by the MySQL `BEFORE UPDATE` trigger (`trg_validate_incident_status`).*

---

## 10. Future Enhancements

- **Role-Based Access Control (RBAC)**: Support for distinct Admin, Analyst, and Auditor credentials.
- **Webhook Integrations**: Automated incident ingestion from SIEM/EDR platforms (e.g., Splunk, Sentinel, Wazuh).
- **Automated Playbooks**: Predefined mitigation workflows for specific attack types.
- **Export Capabilities**: PDF and CSV incident executive briefings and compliance reports.
