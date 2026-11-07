"""
CyberShield — Secure Administrator Provisioning Utility
=======================================================
Command-line utility to provision the initial or subsequent administrator
accounts for the CyberShield platform.

Usage (Interactive):
    python create_admin.py

Usage (Non-interactive flags):
    python create_admin.py --full-name "Security Admin" --username "admin" --email "admin@cybershield.local" --password "SecurePass123!"
"""

import sys
import argparse
import getpass
import re
from werkzeug.security import generate_password_hash
from app import get_db


def validate_email(email: str) -> bool:
    """Validate email syntax."""
    pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
    return bool(re.match(pattern, email))


def create_admin_account(full_name: str, username: str, email: str, password: str) -> bool:
    """
    Securely hash password and insert administrator into the users table.
    Ensures role is ADMIN and no duplicate username or email exists.
    """
    full_name = full_name.strip()
    username = username.strip()
    email = email.strip().lower()

    if not full_name:
        print("[ERROR] Full name cannot be empty.", file=sys.stderr)
        return False

    if not username or len(username) < 3:
        print("[ERROR] Username must be at least 3 characters long.", file=sys.stderr)
        return False

    if not validate_email(email):
        print(f"[ERROR] '{email}' is not a valid email address.", file=sys.stderr)
        return False

    if not password or len(password) < 8:
        print("[ERROR] Password must be at least 8 characters long.", file=sys.stderr)
        return False

    conn = get_db()
    try:
        cursor = conn.cursor(dictionary=True)

        # 1. Fetch ADMIN role_id
        cursor.execute("SELECT role_id FROM roles WHERE role_name = 'ADMIN' LIMIT 1")
        role_row = cursor.fetchone()
        if not role_row:
            print("[ERROR] 'ADMIN' role does not exist in the database. Please seed the roles table first.", file=sys.stderr)
            return False
        admin_role_id = role_row["role_id"]

        # 2. Check for existing username or email
        cursor.execute("SELECT username, email FROM users WHERE username = %s OR email = %s LIMIT 1", (username, email))
        existing = cursor.fetchone()
        if existing:
            if existing["username"].lower() == username.lower():
                print(f"[ERROR] An account with username '{username}' already exists.", file=sys.stderr)
            else:
                print(f"[ERROR] An account with email '{email}' already exists.", file=sys.stderr)
            return False

        # 3. Securely hash password
        password_hash = generate_password_hash(password)

        # 4. Insert into database
        cursor.execute("""
            INSERT INTO users (full_name, username, email, password_hash, role_id, account_status, created_at)
            VALUES (%s, %s, %s, %s, %s, 'ACTIVE', NOW())
        """, (full_name, username, email, password_hash, admin_role_id))
        conn.commit()

        print(f"[SUCCESS] Administrator account '{username}' ({email}) created successfully.")
        return True

    except Exception as e:
        print(f"[ERROR] Database operation failed: {e}", file=sys.stderr)
        return False
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description="CyberShield Administrator Account Provisioning")
    parser.add_argument("--full-name", dest="full_name", help="Administrator's full name")
    parser.add_argument("--username", dest="username", help="Administrator username")
    parser.add_argument("--email", dest="email", help="Administrator email address")
    parser.add_argument("--password", dest="password", help="Administrator password (optional, prompted securely if omitted)")

    args = parser.parse_args()

    # If any required flag is missing, run in interactive mode
    if not args.full_name or not args.username or not args.email or not args.password:
        print("=" * 60)
        print("CyberShield — Initial Administrator Setup")
        print("=" * 60)
        
        full_name = args.full_name or input("Full Name: ").strip()
        username = args.username or input("Username: ").strip()
        email = args.email or input("Email Address: ").strip()

        if args.password:
            password = args.password
        else:
            password = getpass.getpass("Password (min 8 characters): ")
            confirm = getpass.getpass("Confirm Password: ")
            if password != confirm:
                print("[ERROR] Passwords do not match. Aborting.", file=sys.stderr)
                sys.exit(1)
    else:
        full_name = args.full_name
        username = args.username
        email = args.email
        password = args.password

    success = create_admin_account(full_name, username, email, password)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
