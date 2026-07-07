import sqlite3
import hashlib
import secrets
from datetime import datetime

AUTH_DB_PATH = "/home/ubuntu/gophish/auth.db"

def hash_password(password):
    """Hash password with salt"""
    salt = secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return f"{salt}${pwd_hash.hex()}"

def setup_database():
    """Initialize authentication database with default admin"""
    conn = sqlite3.connect(AUTH_DB_PATH)
    cur = conn.cursor()
    
    # Create tables
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        email TEXT,
        is_admin INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    cur.execute("""
    CREATE TABLE IF NOT EXISTS sub_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        parent_id INTEGER NOT NULL,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        email TEXT,
        permissions TEXT DEFAULT 'view',
        is_active INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (parent_id) REFERENCES users(id)
    )
    """)
    
    cur.execute("""
    CREATE TABLE IF NOT EXISTS login_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        ip_address TEXT,
        login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        success INTEGER DEFAULT 1
    )
    """)
    
    # Check if admin already exists
    cur.execute("SELECT id FROM users WHERE username='admin'")
    if not cur.fetchone():
        # Create default admin account
        admin_password = "Admin@123"
        admin_hash = hash_password(admin_password)
        
        cur.execute("""
        INSERT INTO users (username, password_hash, email, is_admin)
        VALUES (?, ?, ?, ?)
        """, ("admin", admin_hash, "admin@gophish.local", 1))
        
        print("\n" + "="*60)
        print("✓ DATABASE INITIALIZATION SUCCESSFUL!")
        print("="*60)
        print("\nDEFAULT ADMIN CREDENTIALS:")
        print("-" * 60)
        print(f"  Username: admin")
        print(f"  Password: {admin_password}")
        print("-" * 60)
        print("\n📝 NEXT STEPS:")
        print("  1. Run: python app.py")
        print("  2. Open: http://localhost:5050")
        print("  3. Login with credentials above")
        print("  4. Go to Admin Panel to create sub-users")
        print("\n⚠️  IMPORTANT: Change admin password after first login!")
        print("="*60 + "\n")
    else:
        print("✓ Database already initialized. Admin user exists.")
    
    conn.commit()
    conn.close()

if __name__ == "__main__":
    setup_database()
