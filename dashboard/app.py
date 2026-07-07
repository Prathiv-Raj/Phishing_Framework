from flask import Flask, render_template_string, request, send_file, redirect, url_for, session
from werkzeug.middleware.proxy_fix import ProxyFix
import sqlite3
from datetime import datetime, timedelta, timezone
from io import BytesIO
import hashlib
import secrets
from functools import wraps
import urllib.request
import os 
import tempfile

from reportlab.lib.pagesizes import A4, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

# =========================
# CONFIG
# =========================
DB_PATH = "/home/cyber-bot/abphish/data/abphish.db"
AUTH_DB_PATH = "/home/cyber-bot/abphish/data/auth.db"
TRAINING_DB_PATH = "/home/cyber-bot/abphish/data/training_status.db"
PORT = 5050



APP_TIMEZONE = timezone(timedelta(hours=5, minutes=30))
APP_TIMEZONE_LABEL = "IST"
DB_NAIVE_TIMEZONE = APP_TIMEZONE

APP_NAME = "Adamsbridge"
REPORT_TITLE = "Phishing Campaign Report"
LOGO_DATA_URI = "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQ0SuEkshsjLKplBwSW40EE50zSVHoYIn33py8bVmY_oQ&s"
PDF_LOGO_LOCAL_PATH = "/home/cyber-bot/abphish/static/adamsbridge-logo.png"

# Standard security colors
PRIMARY_COLOR = "#003133"
ACCENT_COLOR = "#F5A94F"
INFO_COLOR = "#28A745"
LOW_COLOR = "#28A745"
MEDIUM_COLOR = "#F59E0B"
HIGH_COLOR = "#FF0000"
CRITICAL_COLOR = "#8B0000"
PRONE_COLOR = "#1976D2"

app = Flask(__name__)
# Trust one proxy layer when running behind Nginx / Docker proxy.
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Persistent secret key so login sessions survive gunicorn/container restarts.
_secret_key_file = os.path.join(os.path.dirname(AUTH_DB_PATH), ".flask_secret")
if os.environ.get("SECRET_KEY"):
    app.secret_key = os.environ["SECRET_KEY"]
elif os.path.exists(_secret_key_file):
    with open(_secret_key_file, "r") as _f:
        app.secret_key = _f.read().strip()
else:
    app.secret_key = secrets.token_hex(32)
    try:
        with open(_secret_key_file, "w") as _f:
            _f.write(app.secret_key)
    except Exception:
        pass

# Allow session cookies to work correctly behind HTTPS reverse proxy / iframe.
app.config["SESSION_COOKIE_SAMESITE"] = "None"
app.config["SESSION_COOKIE_SECURE"] = True


# =========================
# AUTH DB
# ========================= 
def init_auth_db():
    conn = sqlite3.connect(AUTH_DB_PATH)
    cur = conn.cursor()
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

    cur.execute("""
    CREATE TABLE IF NOT EXISTS active_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_token TEXT UNIQUE NOT NULL,
        user_id INTEGER,
        username TEXT,
        ip_address TEXT,
        user_agent TEXT,
        login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_admin INTEGER DEFAULT 0,
        is_active INTEGER DEFAULT 1
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS training_status (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        uid TEXT UNIQUE,
        campaign_id TEXT,
        campaign_name TEXT,
        first_name TEXT,
        last_name TEXT,
        email TEXT,
        status TEXT DEFAULT 'Pending',
        video_started_at TIMESTAMP,
        completed_at TIMESTAMP,
        certificate_downloaded INTEGER DEFAULT 0,
        certificate_downloaded_at TIMESTAMP
    )
    """)

    # Create default admin only when there are no users.
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        cur.execute(
            "INSERT INTO users (username, password_hash, email, is_admin) VALUES (?, ?, ?, 1)",
            ("admin", hash_password("admin123"), "",),
        )
    conn.commit()
    conn.close()


def hash_password(password):
    salt = secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
    return f"{salt}${pwd_hash.hex()}"


def verify_password(password, password_hash):
    try:
        salt, pwd_hash = password_hash.split("$")
        new_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
        return new_hash.hex() == pwd_hash
    except Exception:
        return False


def log_login(username, ip_address, success=1):
    conn = sqlite3.connect(AUTH_DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO login_logs (username, ip_address, success) VALUES (?, ?, ?)",
        (username, ip_address, success),
    )
    conn.commit()
    conn.close()


def create_active_session(user_id, username, is_admin):
    token = secrets.token_urlsafe(32)
    conn = sqlite3.connect(AUTH_DB_PATH)
    cur = conn.cursor()
    cur.execute("""
    INSERT INTO active_sessions (session_token, user_id, username, ip_address, user_agent, is_admin, is_active)
    VALUES (?, ?, ?, ?, ?, ?, 1)
    """, (token, user_id, username, request.remote_addr, request.headers.get("User-Agent", ""), 1 if is_admin else 0))
    conn.commit()
    conn.close()
    return token


def deactivate_active_session(token):
    if not token:
        return
    conn = sqlite3.connect(AUTH_DB_PATH)
    cur = conn.cursor()
    cur.execute("UPDATE active_sessions SET is_active=0 WHERE session_token=?", (token,))
    conn.commit()
    conn.close()


@app.before_request
def enforce_active_session():
    if request.endpoint in ("login", "static"):
        return
    token = session.get("session_token")
    if not token:
        return
    conn = sqlite3.connect(AUTH_DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT is_active FROM active_sessions WHERE session_token=?", (token,))
    row = cur.fetchone()
    if not row or row[0] != 1:
        conn.close()
        session.clear()
        return redirect(url_for("login"))
    cur.execute("UPDATE active_sessions SET last_seen=CURRENT_TIMESTAMP WHERE session_token=?", (token,))
    conn.commit()
    conn.close()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        if not session.get("is_admin"):
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated_function


# =========================
# DATA HELPERS
# =========================
def parse_app_datetime(value):
    """Parse DB timestamps and return timezone-aware IST datetime.

    Naive SQLite timestamps are treated as IST/local dashboard time.
    This prevents adding +5:30 again and avoids start/completed mismatch.
    """
    if not value:
        return None
    text = str(value).strip()
    if not text or text.upper() in ("N/A", "NONE", "NULL"):
        return None

    # Normalize dashboard/display values also.
    # Example supported: "26-06-2026 12:25:52 PM IST"
    if text.upper().endswith(" IST"):
        text = text[:-4].strip()

    # Normalize common DB formats.
    text = text.replace("Z", "+00:00")
    if "." in text and "+" not in text and "-" in text[:10]:
        text = text.split(".")[0]

    formats = (
        None,
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%d-%m-%Y %I:%M:%S %p",
        "%d-%m-%Y %I:%M %p",
        "%d-%m-%Y %H:%M:%S",
        "%d-%m-%Y %H:%M",
    )

    for fmt in formats:
        try:
            if fmt is None:
                dt = datetime.fromisoformat(text.replace("T", " "))
            else:
                dt = datetime.strptime(text, fmt)

            # If DB value has no timezone, treat it as IST/local dashboard time.
            # This avoids date/time mismatch caused by adding +5:30 again.
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=DB_NAIVE_TIMEZONE)
            return dt.astimezone(APP_TIMEZONE)
        except Exception:
            continue
    return None


def clean_time(value):
    dt = parse_app_datetime(value)
    if not dt:
        return "N/A" if not value else str(value).split(".")[0]
    return dt.strftime("%d-%m-%Y %I:%M:%S %p") + " " + APP_TIMEZONE_LABEL


def clean_date(value):
    dt = parse_app_datetime(value)
    if not dt:
        return "N/A"
    return dt.strftime("%d-%m-%Y")

def normalize_start_completed(started_value, completed_value):
    """Return display-safe start/completed timestamps in IST.

    Rules:
    - If completed_at is earlier than started_at due to old mixed UTC/IST data,
      display completed_at as started_at also.
    - This prevents impossible rows like completed before started.
    """
    started_dt = parse_app_datetime(started_value)
    completed_dt = parse_app_datetime(completed_value)

    if started_dt and completed_dt and completed_dt < started_dt:
        return completed_value, completed_value

    return started_value, completed_value


def latest_event_time_for_uid_or_email(uid, email, campaign_id):
    """Find latest abphish Clicked Link time for accurate Recent Clicked display."""
    try:
        conn = get_db()
        cur = conn.cursor()
        params = []
        where = ["events.message = 'Clicked Link'"]

        if uid:
            where.append("results.r_id = ?")
            params.append(uid)
        else:
            where.append("LOWER(events.email) = ?")
            params.append((email or "").strip().lower())

        if campaign_id:
            where.append("events.campaign_id = ?")
            params.append(campaign_id)

        q = """
        SELECT events.time
        FROM events
        LEFT JOIN results
          ON events.email = results.email
          AND events.campaign_id = results.campaign_id
        WHERE """ + " AND ".join(where) + """
        ORDER BY events.time DESC
        LIMIT 1
        """
        cur.execute(q, params)
        row = cur.fetchone()
        conn.close()
        return row[0] if row else None
    except Exception:
        return None


def days_overdue_from(due_value):
    due = parse_app_datetime(due_value)
    if not due:
        return 0
    now = datetime.now(APP_TIMEZONE)
    if now <= due:
        return 0
    return max(1, (now.date() - due.date()).days)


def app_now_db():
    """Return dashboard timestamp in IST without timezone suffix for SQLite storage."""
    return datetime.now(APP_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")



def normalize_event_name(message):
    """Normalize abphish event names safely."""
    return str(message or "").strip().lower()


def is_sent_event(message):
    m = normalize_event_name(message)
    return m in ("email sent", "sent") or ("email" in m and "sent" in m)


def is_opened_event(message):
    m = normalize_event_name(message)
    return m in ("email opened", "opened") or ("email" in m and ("open" in m or "opened" in m))


def is_clicked_event(message):
    """Accept common abphish click event name variations."""
    m = normalize_event_name(message)
    return (
        m in ("clicked link", "link clicked", "clicked", "email clicked", "email link clicked")
        or ("click" in m and "campaign" not in m)
        or ("link" in m and "click" in m)
    )


def is_submitted_event(message):
    """Accept common submitted-data event name variations."""
    m = normalize_event_name(message)
    return (
        m in ("submitted data", "data submitted", "submitted credentials", "credentials submitted")
        or ("submit" in m)
        or ("credential" in m and ("submit" in m or "post" in m))
    )

def severity_level(message):
    # Activity severity mapping
    if is_submitted_event(message):
        return "Critical"
    if is_clicked_event(message):
        return "High"
    if is_opened_event(message):
        return "Medium"
    if is_sent_event(message):
        return "Low"
    return "Medium"


def severity_order(message):
    if is_submitted_event(message):
        return 1
    if is_clicked_event(message):
        return 2
    if is_opened_event(message):
        return 3
    if is_sent_event(message):
        return 4
    return 3


def get_db():
    return sqlite3.connect(DB_PATH)


def get_campaigns():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, name FROM campaigns ORDER BY id DESC")
    campaigns = cur.fetchall()
    conn.close()
    return campaigns


def get_recent_campaign_id():
    campaigns = get_campaigns()
    return str(campaigns[0][0]) if campaigns else "all"


def resolve_campaign_id(campaign_id):
    if campaign_id in (None, "", "recent"):
        return get_recent_campaign_id()
    return campaign_id


def get_campaign_rows(campaign_id="recent", filter_type=None):
    campaign_id = resolve_campaign_id(campaign_id)
    conn = get_db()
    cur = conn.cursor()

    query = """
    SELECT
        campaigns.name,
        COALESCE(results.first_name, '') AS first_name,
        COALESCE(results.last_name, '') AS last_name,
        events.email,
        events.message,
        events.time
    FROM events
    LEFT JOIN campaigns ON events.campaign_id = campaigns.id
    LEFT JOIN results
        ON events.email = results.email
        AND events.campaign_id = results.campaign_id
    """

    params = []
    where = []
    if campaign_id != "all":
        where.append("events.campaign_id = ?")
        params.append(campaign_id)
    # Hide abphish system event from dashboard/activity log
    where.append("events.message != ?")
    params.append("Campaign Created")

    if filter_type:
        where.append("events.message = ?")
        params.append(filter_type)
    if where:
        query += " WHERE " + " AND ".join(where)

    # Activity Log order: Critical → High → Medium → Low → Info, then recent time.
    query += """
    ORDER BY
        CASE events.message
            WHEN 'Submitted Data' THEN 1
            WHEN 'Clicked Link' THEN 2
            WHEN 'Email Opened' THEN 3
            WHEN 'Email Sent' THEN 4
            ELSE 3
        END ASC,
        events.time DESC
    """

    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()
    return rows


def get_campaign_name(campaign_id):
    campaign_id = resolve_campaign_id(campaign_id)
    if campaign_id == "all":
        return "All Campaigns"
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT name FROM campaigns WHERE id=?", (campaign_id,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else "Unknown Campaign"


def calculate_stats(rows):
    # Raw event counts for dashboard cards/charts.
    sent = sum(1 for r in rows if is_sent_event(r[4]))
    opened = sum(1 for r in rows if is_opened_event(r[4]))
    clicked = sum(1 for r in rows if is_clicked_event(r[4]))
    submitted = sum(1 for r in rows if is_submitted_event(r[4]))

    # Campaign Phish-prone Percentage (PPP)
    # Formula: (Total Failures / Total Emails Delivered) * 100
    # Total Emails Delivered = Email Sent count from abphish events.
    # Total Failures = UNIQUE users who clicked link OR submitted data.
    # Same user click + submit pannaalum 1 failure mattum count pannum.
    total_delivered = sent

    failure_map = {}
    for r in rows:
        campaign_name = str(r[0] or "Unknown Campaign").strip()
        email = str(r[3] or "").strip().lower()
        event_name = str(r[4] or "").strip()

        if not email:
            continue

        clicked_event = is_clicked_event(event_name)
        submitted_event = is_submitted_event(event_name)

        # Clicked Link and Submitted Data both are failures.
        if not (clicked_event or submitted_event):
            continue

        failure_key = (campaign_name, email)
        name = ((str(r[1] or "") + " " + str(r[2] or "")).strip()) or "N/A"

        if failure_key not in failure_map:
            failure_map[failure_key] = {
                "campaign": campaign_name,
                "name": name,
                "email": email,
                "clicked": False,
                "submitted": False,
                "clicked_time": "",
                "submitted_time": "",
                "time": "",
            }

        item = failure_map[failure_key]

        if clicked_event:
            item["clicked"] = True
            item["clicked_time"] = clean_time(r[5])
        if submitted_event:
            item["submitted"] = True
            item["submitted_time"] = clean_time(r[5])

        item["time"] = item["submitted_time"] or item["clicked_time"]

    failure_users = []
    for item in failure_map.values():
        if item["clicked"] and item["submitted"]:
            item["event"] = "Clicked Link + Submitted Data"
        elif item["submitted"]:
            item["event"] = "Submitted Data"
        else:
            item["event"] = "Clicked Link"
        failure_users.append(item)

    total_failures = len(failure_users)
    prone = round((total_failures / total_delivered) * 100, 2) if total_delivered > 0 else 0

    total_events = sent + opened + clicked + submitted
    return {
        "sent": sent,
        "opened": opened,
        "clicked": clicked,
        "submitted": submitted,
        "total_delivered": total_delivered,
        "total_failures": total_failures,
        "failure_users": failure_users,
        "delivered": total_delivered,
        "failures": total_failures,
        "prone": prone,
        "critical": submitted,
        "high": clicked,
        "medium": opened,
        "low": sent,
        "total": total_events,
    }


def get_current_user():
    return session.get("username", "user"), bool(session.get("is_admin"))



def get_abphish_user_by_uid(uid):
    """Return user/campaign details using abphish result UID."""
    default = {
        "uid": uid or "",
        "campaign_id": "",
        "campaign_name": "Unknown Campaign",
        "first_name": "User",
        "last_name": "",
        "email": "Unknown"
    }

    if not uid:
        return default

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
        SELECT
            COALESCE(results.first_name, ''),
            COALESCE(results.last_name, ''),
            COALESCE(results.email, ''),
            COALESCE(campaigns.id, ''),
            COALESCE(campaigns.name, 'Unknown Campaign')
        FROM results
        LEFT JOIN campaigns ON results.campaign_id = campaigns.id
        WHERE results.r_id = ?
        LIMIT 1
        """, (uid,))
        row = cur.fetchone()
        conn.close()
        if row:
            return {
                "uid": uid,
                "first_name": row[0] or "User",
                "last_name": row[1] or "",
                "email": row[2] or "Unknown",
                "campaign_id": str(row[3] or ""),
                "campaign_name": row[4] or "Unknown Campaign"
            }
    except Exception:
        pass

    return default


def upsert_training_status(uid, status="Pending", mark_certificate=False):
    user = get_abphish_user_by_uid(uid)
    now = app_now_db()

    conn = sqlite3.connect(AUTH_DB_PATH)
    cur = conn.cursor()

    cur.execute("SELECT id FROM training_status WHERE uid = ?", (uid,))
    exists = cur.fetchone()

    if exists:
        if status == "Completed":
            cur.execute("""
            UPDATE training_status
            SET campaign_id=?, campaign_name=?, first_name=?, last_name=?, email=?,
                status='Completed', completed_at=COALESCE(completed_at, ?)
            WHERE uid=?
            """, (user["campaign_id"], user["campaign_name"], user["first_name"], user["last_name"], user["email"], now, uid))
        else:
            cur.execute("""
            UPDATE training_status
            SET campaign_id=?, campaign_name=?, first_name=?, last_name=?, email=?,
                video_started_at=COALESCE(video_started_at, ?)
            WHERE uid=?
            """, (user["campaign_id"], user["campaign_name"], user["first_name"], user["last_name"], user["email"], now, uid))
    else:
        cur.execute("""
        INSERT INTO training_status
        (uid, campaign_id, campaign_name, first_name, last_name, email, status, video_started_at, completed_at, certificate_downloaded, certificate_downloaded_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            uid,
            user["campaign_id"],
            user["campaign_name"],
            user["first_name"],
            user["last_name"],
            user["email"],
            status,
            now,
            now if status == "Completed" else None,
            1 if mark_certificate else 0,
            now if mark_certificate else None,
        ))

    conn.commit()
    conn.close()
    return user


# =========================
# CSS
# IMPORTANT: This is a normal string, not f-string, so CSS braces will not break Python.
# =========================
BASE_CSS = """
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: #f4f7f8;
    color: #003133;
    min-height: 100vh;
}
.sidebar {
    position: fixed;
    top: 0;
    left: 0;
    width: 255px;
    height: 100vh;
    background: linear-gradient(180deg, #003133 0%, #004446 100%);
    padding: 28px 18px;
    color: #fff;
    display: flex;
    flex-direction: column;
    box-shadow: 4px 0 20px rgba(0,0,0,0.18);
    z-index: 10;
}
.sidebar-brand {
    padding-bottom: 22px;
    border-bottom: 1px solid rgba(245,169,79,0.35);
    margin-bottom: 28px;
}
.sidebar-brand .brand-logo {
    width: 210px;
    height: auto;
    display: block;
    object-fit: contain;
}
.sidebar nav {
    display: flex;
    flex-direction: column;
    gap: 10px;
}
.sidebar a {
    display: flex;
    align-items: center;
    gap: 12px;
    color: rgba(255,255,255,0.88);
    text-decoration: none;
    padding: 14px 16px;
    border-radius: 10px;
    font-size: 15px;
    font-weight: 650;
    border-left: 4px solid transparent;
    transition: all .2s ease;
}
.sidebar a:hover,
.sidebar a.active {
    background: rgba(0, 101, 104, 0.8);
    color: #F5A94F;
    border-left-color: #F5A94F;
}
.nav-icon { width: 22px; text-align: center; }
.sidebar-user {
    margin-top: auto;
    border: 1px solid rgba(245,169,79,0.8);
    border-radius: 10px;
    padding: 14px 16px;
    display: flex;
    gap: 12px;
    align-items: center;
    background: rgba(255,255,255,0.06);
}
.avatar {
    width: 44px;
    height: 44px;
    border-radius: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    background: rgba(255,255,255,0.18);
    color: #F5A94F;
    font-weight: 800;
    font-size: 20px;
}
.user-name { font-size: 14px; font-weight: 800; color: #fff; }
.user-role { font-size: 13px; font-weight: 750; color: #F5A94F; margin-top: 4px; }
.main {
    margin-left: 255px;
    padding: 28px 30px 45px;
}
.topbar,
.panel,
.chart-panel {
    background: #fff;
    border-radius: 12px;
    box-shadow: 0 2px 14px rgba(0,0,0,0.08);
}
.topbar {
    padding: 24px 28px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 3px solid #F5A94F;
    margin-bottom: 26px;
}
.topbar h2 { font-size: 25px; line-height: 1.1; color: #003133; }
.topbar p { color: #667785; margin-top: 8px; font-size: 14px; }
.topbar-title-row { display:flex; align-items:center; gap:16px; }
.topbar-logo { width:190px; max-height:52px; object-fit:contain; display:block; }
.filter-tabs { display:flex; gap:14px; flex-wrap:wrap; margin-bottom:24px; }
.filter-tab { min-width:210px; flex:1; background:#fff; border-radius:12px; padding:18px 20px; box-shadow:0 2px 14px rgba(0,0,0,.08); border-top:5px solid #ddd; text-decoration:none; color:#003133; font-weight:900; transition:all .2s ease; }
.filter-tab:hover { transform:translateY(-2px); box-shadow:0 8px 20px rgba(0,0,0,.13); }
.filter-tab h1 { font-size:32px; margin-bottom:7px; }
.filter-tab p { font-size:13px; text-transform:uppercase; letter-spacing:.5px; color:#647486; font-weight:900; }
.filter-tab.all { border-top-color:#003133; }
.filter-tab.completed { border-top-color:#28A745; }
.filter-tab.pending { border-top-color:#F59E0B; }
.filter-tab.active { color:#fff; }
.filter-tab.all.active { background:#003133; }
.filter-tab.completed.active { background:#28A745; }
.filter-tab.pending.active { background:#F59E0B; }
.filter-tab.active p { color:#fff; }
.topbar-right { display: flex; gap: 14px; align-items: center; }
select, input {
    border: 1.5px solid #cfd8df;
    border-radius: 8px;
    padding: 12px 14px;
    background: #fff;
    color: #003133;
    outline: none;
    font-size: 14px;
}
select { min-width: 190px; }
.btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    border: 0;
    border-radius: 8px;
    padding: 12px 20px;
    font-weight: 800;
    cursor: pointer;
    text-decoration: none;
    transition: all .2s ease;
}
.btn-primary { background: #003133; color: #fff; }
.btn-primary:hover { background: #004d50; transform: translateY(-1px); }
.btn-gold { background: #C9A961; color: #003133; }
.btn-danger { background: #EF1C25; color: #fff; }
.cards {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 16px;
    margin-bottom: 26px;
}
.card {
    background: #fff;
    min-height: 162px;
    border-radius: 12px;
    padding: 24px 22px;
    box-shadow: 0 2px 14px rgba(0,0,0,0.08);
    text-decoration: none;
    color: #003133;
    border-top: 5px solid #ddd;
}
.card{
    transition: all .25s ease;
    cursor: pointer;
}
.card:hover{
    transform: translateY(-3px);
    box-shadow: 0 8px 22px rgba(0,0,0,.13);
}
.card.active-card{
    transform: translateY(-5px);
    box-shadow: 0 12px 28px rgba(0,0,0,.22);
}
.card-sent.active-card{
    background:#28A745;
    border-top:5px solid #1E7E34;
}
.card-opened.active-card{
    background:#F59E0B;
    border-top:5px solid #D97706;
}
.card-clicked.active-card{
    background:#FF0000;
    border-top:5px solid #B91C1C;
}
.card-submitted.active-card{
    background:#8B0000;
    border-top:5px solid #5F0000;
}
.card-risk.active-card{
    background:#1976D2;
    border-top:5px solid #1565C0;
}
.card.active-card h1,
.card.active-card p,
.card.active-card .card-icon{
    color:#fff !important;
}
.card.active-card .card-icon{
    background:rgba(255,255,255,.20) !important;
}

.card-icon {
    width: 46px;
    height: 46px;
    border-radius: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 22px;
    margin-bottom: 18px;
}
.card h1 { font-size: 37px; line-height: 1; font-weight: 900; margin-bottom: 8px; }
.card p { font-size: 13px; color: #647486; font-weight: 900; text-transform: uppercase; letter-spacing: .5px; }
.card-sent { border-top-color: #28A745; }
.card-opened { border-top-color: #F59E0B; }
.card-clicked { border-top-color: #FF0000; }
.card-submitted { border-top-color: #8B0000; }
.card-risk { border-top-color: #1976D2; }
.card-sent h1 { color: #28A745; }
.card-opened h1 { color: #F59E0B; }
.card-clicked h1 { color: #FF0000; }
.card-submitted h1 { color: #8B0000; }
.card-risk h1 { color: #1976D2; }
.card-sent .card-icon { background: rgba(40,167,69,.10); color: #28A745; }
.card-opened .card-icon { background: rgba(245,158,11,.12); color: #F59E0B; }
.card-clicked .card-icon { background: rgba(255,0,0,.10); color: #FF0000; }
.card-submitted .card-icon { background: rgba(139,0,0,.10); color: #8B0000; }
.card-risk .card-icon { background: rgba(25,118,210,.10); color: #1976D2; }
.chart-panel { padding: 24px 28px; margin-bottom: 26px; }
.chart-panel-header { display:flex; justify-content:space-between; align-items:center; margin-bottom:16px; }
.chart-panel-header h3 { font-size: 19px; color:#003133; }
.chart-legend { display:flex; gap:24px; flex-wrap:wrap; font-size:14px; }
.legend-item { display:flex; align-items:center; gap:8px; }
.legend-dot { width:11px; height:11px; border-radius:50%; }
.chart-grid { display:grid; grid-template-columns: 1fr 1fr; gap:16px; }
.chart-box {
    background:#fbfcfd;
    border:1px solid #d8e0e5;
    border-radius:8px;
    padding:18px;
    min-height: 330px;
    overflow: hidden;
}
.chart-box h4 { font-size:14px; font-weight:900; text-transform:uppercase; margin-bottom:10px; }
.chart-canvas-wrap { height:260px; position:relative; }
.donut-area { height:260px; display:grid; grid-template-columns: 1fr 190px; gap:16px; align-items:center; }
.donut-wrap { height:250px; position:relative; }
.donut-center {
    position:absolute;
    top:50%; left:50%; transform:translate(-50%,-50%);
    text-align:center;
    pointer-events:none;
    font-weight:800;
    color:#003133;
}
.donut-center .total { font-size:30px; line-height:1; margin:6px 0; }
.sev-legend { display:flex; flex-direction:column; gap:16px; font-size:15px; }
.sev-legend div { display:flex; align-items:center; gap:10px; }
.sev-box { width:18px; height:12px; border-radius:3px; display:inline-block; }
.panel { padding: 22px 28px; }
.panel-header { display:flex; align-items:center; justify-content:space-between; gap:14px; margin-bottom:14px; }
.panel-header h3 { font-size:19px; }
.search-box { width: 255px; }
.search-box input { width:100%; padding:10px 13px; }
table { width:100%; border-collapse: collapse; font-size:14px; overflow:hidden; }
thead th {
    background: linear-gradient(90deg, #003133, #005356);
    color:#fff;
    text-align:left;
    padding: 13px 12px;
    font-size:13px;
}
tbody td { padding: 12px; border-bottom:1px solid #e8edf0; }
tbody tr:nth-child(even) { background:#fafafa; }
tbody tr:hover { background:#fff7e9; }
.badge { display:inline-block; padding:5px 10px; border-radius:6px; font-size:12px; font-weight:850; color:#fff; }
.badge.critical { background:#8B0000; }
.badge.high { background:#FF0000; }
.badge.medium { background:#F59E0B; }
.badge.low { background:#28A745; }
.badge.combo { background:#6D28D9; }

.login-container {
    min-height:100vh;
    display:flex;
    align-items:center;
    justify-content:center;
    background: linear-gradient(135deg, #003133, #005356);
}
.login-box {
    background:#fff;
    border-radius:16px;
    width:410px;
    padding:42px;
    box-shadow:0 20px 60px rgba(0,0,0,.25);
}
.login-logo { text-align:center; margin-bottom:30px; }
.login-logo img { max-width:260px; height:auto; }
.login-box button { width:100%; }
.alert { padding:12px 14px; border-radius:8px; margin-bottom:15px; background:#ffe5e5; color:#8B0000; font-weight:700; }
.form-group { margin-bottom:16px; }
.form-group label { display:block; font-size:13px; font-weight:800; margin-bottom:7px; text-transform:uppercase; }
.form-group input, .form-group select { width:100%; }
.permission-badge { padding:5px 10px; border-radius:6px; background:#fff2d8; color:#8a5a00; font-weight:800; }
.filter-tab.recent { border-top-color:#1976D2; }
.filter-tab.overdue { border-top-color:#8B0000; }
.filter-tab.recent.active { background:#1976D2; }
.filter-tab.overdue.active { background:#8B0000; }
.badge.success { background:#28A745; }
.badge.failed { background:#FF0000; }
.badge.info { background:#1976D2; }
.badge.overdue { background:#8B0000; }
.btn-small { padding:7px 12px; font-size:12px; border-radius:6px; }
.panel-actions { display:flex; gap:10px; align-items:center; flex-wrap:wrap; }
.btn-outline { background:#fff; color:#003133; border:1.5px solid #cfd8df; }
.btn-outline:hover { background:#f4f7f8; }


.summary-click-row { cursor: pointer; }
.summary-click-row:hover { background:#fff7e9 !important; }
.summary-link { color:#003133; text-decoration:none; font-weight:900; }
.summary-link:hover { color:#F59E0B; text-decoration:underline; }
.selected-campaign-note { margin-bottom:12px; font-size:13px; color:#667785; font-weight:800; }

.ppp-hint { font-size:11px; color:#667785; margin-top:8px; font-weight:800; }
.ppp-click { font-size:11px; color:#1976D2; margin-top:6px; font-weight:900; }
.modal-overlay { display:none; position:fixed; inset:0; background:rgba(0,0,0,.55); z-index:9999; align-items:center; justify-content:center; padding:20px; }
.modal-box { background:#fff; width:min(760px, 96vw); max-height:88vh; overflow:auto; border-radius:14px; box-shadow:0 24px 80px rgba(0,0,0,.35); border-top:6px solid #1976D2; }
.modal-header { padding:20px 24px; display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid #e8edf0; }
.modal-header h3 { color:#003133; font-size:20px; }
.modal-close { border:0; background:#8B0000; color:#fff; border-radius:8px; padding:8px 12px; font-weight:900; cursor:pointer; }
.modal-body { padding:22px 24px; }
.formula-box { background:#f4f7f8; border-left:5px solid #1976D2; padding:14px 16px; border-radius:8px; font-weight:900; margin-bottom:16px; }
.calc-grid { display:grid; grid-template-columns:repeat(3, 1fr); gap:12px; margin:16px 0; }
.calc-card { border:1px solid #d8e0e5; border-radius:10px; padding:14px; background:#fbfcfd; }
.calc-card h2 { font-size:26px; margin-bottom:4px; }
.calc-card p { font-size:12px; font-weight:900; color:#647486; text-transform:uppercase; }
.step-box { background:#fff7e9; border:1px solid #F5A94F; border-radius:10px; padding:14px 16px; font-weight:900; margin:16px 0; }
.note-box { background:#eef7ff; border-left:5px solid #1976D2; padding:12px 14px; border-radius:8px; margin:16px 0; font-size:13px; font-weight:750; }

@media(max-width:1200px) {
    .cards { grid-template-columns: repeat(3,1fr); }
    .chart-grid { grid-template-columns:1fr; }
}
@media(max-width:768px) {
    .sidebar { position:relative; width:100%; height:auto; }
    .main { margin-left:0; padding:18px; }
    .cards { grid-template-columns:1fr; }
    .topbar, .panel-header { flex-direction:column; align-items:flex-start; }
}
</style>
"""


# =========================
# SHARED SIDEBAR
# =========================
def sidebar_html(username, is_admin, active="dashboard"):
    initial = (username[:1] or "A").upper()
    role_label = "Admin" if is_admin else "User"
    admin_link = ""
    if is_admin:
        admin_active = "active" if active == "admin" else ""
        admin_link = f'<a href="/admin" class="{admin_active}"><span class="nav-icon">⚙️</span>Admin Panel</a>'
    return f"""
<div class="sidebar">
  <div class="sidebar-brand">
    <img class="brand-logo" src="https://adamsbridge.com/wp-content/themes/adamsbridge/resources/images/footer-logo.svg" alt="Adamsbridge Logo">
  </div>
  <nav>
    <a href="/" class="{'active' if active == 'dashboard' else ''}"><span class="nav-icon">📊</span>Dashboard</a>
    <a href="/report" class="{'active' if active == 'report' else ''}"><span class="nav-icon">📄</span>Reports</a>
    <a href="/training-users" class="{'active' if active == 'training' else ''}"><span class="nav-icon">🎓</span>Training Users</a>
    {admin_link}
    <a href="/logout"><span class="nav-icon">↪</span>Logout</a>
  </nav>
  <div class="sidebar-user">
    <div class="avatar">{initial}</div>
    <div>
      <div class="user-name">User: {username}</div>
      <div class="user-role">Status: {role_label}</div>
    </div>
  </div>
</div>
"""


# =========================
# ROUTES
# =========================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ip_address = request.remote_addr

        conn = sqlite3.connect(AUTH_DB_PATH)
        cur = conn.cursor()

        cur.execute("SELECT id, password_hash, is_admin FROM users WHERE username=?", (username,))
        user = cur.fetchone()
        if user and verify_password(password, user[1]):
            session["user_id"] = user[0]
            session["username"] = username
            session["is_admin"] = bool(user[2])
            session["session_token"] = create_active_session(user[0], username, bool(user[2]))
            log_login(username, ip_address, 1)
            conn.close()
            return redirect(url_for("dashboard"))

        cur.execute("SELECT id, password_hash, parent_id, is_active FROM sub_users WHERE username=?", (username,))
        sub_user = cur.fetchone()
        if sub_user and sub_user[3] == 1 and verify_password(password, sub_user[1]):
            session["user_id"] = sub_user[0]
            session["username"] = username
            session["is_admin"] = False
            session["parent_id"] = sub_user[2]
            session["session_token"] = create_active_session(sub_user[0], username, False)
            log_login(username, ip_address, 1)
            conn.close()
            return redirect(url_for("dashboard"))

        log_login(username, ip_address, 0)
        conn.close()
        return render_template_string(LOGIN_TEMPLATE, error="Invalid username or password")

    return render_template_string(LOGIN_TEMPLATE, error=None)


@app.route("/logout")
def logout():
    deactivate_active_session(session.get("session_token"))
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    selected = request.args.get("campaign_id", "all")
    filter_type = request.args.get("filter")
    campaigns = get_campaigns()
    resolved_selected = resolve_campaign_id(selected)
    all_rows = get_campaign_rows(selected, None)
    rows = get_campaign_rows(selected, filter_type)
    stats = calculate_stats(all_rows)
    username, is_admin = get_current_user()
    sb = sidebar_html(username, is_admin, active="dashboard")

    html = """<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Campaign Dashboard</title>
""" + BASE_CSS + """
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
</head>
<body>
""" + sb + """
<div class="main">
  <div class="topbar">
    <div class="topbar-title-row">
      <div><h2>Campaign Dashboard</h2>
      <p>Real-time phishing risk monitoring &amp; analysis</p></div>
    </div>
    <div class="topbar-right">
      <select id="campaignSel" onchange="changeCampaign()">
        <option value="all" {% if resolved_selected == 'all' %}selected{% endif %}>All Campaigns</option>
        <option value="recent" {% if selected == 'recent' %}selected{% endif %}>Recent Campaign</option>
        {% for c in campaigns %}
        <option value="{{c[0]}}" {% if resolved_selected == c[0]|string %}selected{% endif %}>{{c[1]}}</option>
        {% endfor %}
      </select>
      <button class="btn btn-primary" onclick="openReport()">📄 Open Report</button>
    </div>
  </div>

  <div class="cards">
    <a href="javascript:filterBy('Email Sent')" class="card card-sent {% if filter == 'Email Sent' %}active-card{% endif %}"><h1>{{stats.sent}}</h1><p>Emails Sent</p></a>
    <a href="javascript:filterBy('Email Opened')" class="card card-opened {% if filter == 'Email Opened' %}active-card{% endif %}"><h1>{{stats.opened}}</h1><p>Emails Opened</p></a>
    <a href="javascript:filterBy('Clicked Link')" class="card card-clicked {% if filter == 'Clicked Link' %}active-card{% endif %}"><h1>{{stats.clicked}}</h1><p>Links Clicked</p></a>
    <a href="javascript:filterBy('Submitted Data')" class="card card-submitted {% if filter == 'Submitted Data' %}active-card{% endif %}"><h1>{{stats.submitted}}</h1><p>Submitted Data</p></a>
    <div class="card card-risk" onclick="showPPPModal()" title="Click to view PPP calculation"><h1>{{stats.prone}}%</h1><p>Phish-Prone Rate</p><div class="ppp-hint">{{stats.total_failures}} failures / {{stats.total_delivered}} delivered</div><div class="ppp-click">ⓘ Click to view calculation</div></div>
  </div>

  <div id="pppModal" class="modal-overlay" onclick="closePPPModal(event)">
    <div class="modal-box">
      <div class="modal-header">
        <h3>Phish-Prone Percentage Calculation</h3>
        <button class="modal-close" onclick="hidePPPModal()">Close</button>
      </div>
      <div class="modal-body">
        <div class="formula-box">PPP = (Total Failures / Total Emails Delivered) × 100</div>
        <div class="calc-grid">
          <div class="calc-card"><h2 style="color:#28A745">{{stats.total_delivered}}</h2><p>Total Emails Delivered</p></div>
          <div class="calc-card"><h2 style="color:#1976D2">{{stats.total_failures}}</h2><p>Unique Failed Users</p></div>
          <div class="calc-card"><h2 style="color:#1976D2">{{stats.prone}}%</h2><p>Final PPP</p></div>
        </div>
        <div class="step-box">
          Calculation: ({{stats.total_failures}} ÷ {{stats.total_delivered}}) × 100 = {{stats.prone}}%
        </div>
        <div class="note-box">
          Total Emails Delivered is taken from the Emails Sent count. Failure means the user clicked the phishing link OR submitted data. If the same user clicked and submitted data in the same campaign, that user is counted only once, but the event will be shown as Clicked Link + Submitted Data.
        </div>
        <h3 style="margin:18px 0 10px">Failed Users Counted in PPP</h3>
        <table>
          <thead><tr><th>#</th><th>Campaign</th><th>Name</th><th>Email</th><th>Failure Event</th><th>Time</th></tr></thead>
          <tbody>
          {% if stats.failure_users %}
            {% for u in stats.failure_users %}
            <tr><td>{{loop.index}}</td><td><b>{{u.campaign}}</b></td><td>{{u.name}}</td><td>{{u.email}}</td><td><span class="badge {% if 'Clicked Link +' in u.event %}combo{% elif u.event == 'Submitted Data' %}critical{% else %}high{% endif %}">{{u.event}}</span></td><td>{{u.time}}</td></tr>
            {% endfor %}
          {% else %}
            <tr><td colspan="6" style="text-align:center;padding:20px;color:#777">No failed users found</td></tr>
          {% endif %}
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <div class="chart-panel">
    <div class="chart-panel-header">
      <h3>Activity Breakdown</h3>
      <div class="chart-legend">
        <span class="legend-item"><span class="legend-dot" style="background:#28A745"></span>Sent</span>
        <span class="legend-item"><span class="legend-dot" style="background:#F59E0B"></span>Opened</span>
        <span class="legend-item"><span class="legend-dot" style="background:#FF0000"></span>Clicked</span>
        <span class="legend-item"><span class="legend-dot" style="background:#8B0000"></span>Submitted</span>
      </div>
    </div>
    <div class="chart-grid">
      <div class="chart-box">
        <h4>Event Volume</h4>
        <div class="chart-canvas-wrap"><canvas id="barChart"></canvas></div>
      </div>
      <div class="chart-box">
        <h4>Severity Distribution</h4>
        <div class="donut-area">
          <div class="donut-wrap">
            <canvas id="donutChart"></canvas>
            <div class="donut-center"><div>Total</div><div class="total">{{stats.total}}</div><div>Events</div></div>
          </div>
          <div class="sev-legend">
            <div><span class="sev-box" style="background:#8B0000"></span>Critical ({{stats.critical}})</div>
            <div><span class="sev-box" style="background:#FF0000"></span>High ({{stats.high}})</div>
            <div><span class="sev-box" style="background:#F59E0B"></span>Medium ({{stats.medium}})</div>
            <div><span class="sev-box" style="background:#28A745"></span>Low ({{stats.low}})</div>
            
          </div>
        </div>
      </div>
    </div>
  </div>

  <div class="panel">
    <div class="panel-header">
      <h3>Activity Log <span style="font-size:13px;color:#667785">(Critical → High → Medium → Low)</span></h3>
      <div class="search-box"><input id="search" onkeyup="searchTable()" placeholder="🔍 Search records..."></div>
    </div>
    {% if filter %}<a class="btn btn-gold" href="/?campaign_id={{selected}}" style="margin-bottom:12px">Clear Filter: {{filter}}</a>{% endif %}
    <table>
      <thead>
        <tr><th>#</th><th>Time</th><th>Campaign</th><th>Name</th><th>Email</th><th>Event</th><th>Severity</th></tr>
      </thead>
      <tbody id="tableBody">
        {% if rows %}
        {% for r in rows %}
        {% set sev = severity_level(r[4]) %}
        <tr>
          <td>{{loop.index}}</td>
          <td>{{clean_time(r[5])}}</td>
          <td><strong>{{r[0]}}</strong></td>
          <td>{{(r[1] ~ ' ' ~ r[2]).strip() or 'N/A'}}</td>
          <td>{{r[3]}}</td>
          <td>{{r[4]}}</td>
          <td><span class="badge {{sev|lower}}">{{sev}}</span></td>
        </tr>
        {% endfor %}
        {% else %}
        <tr><td colspan="10" style="text-align:center;padding:35px;color:#777">No records found</td></tr>
        {% endif %}
      </tbody>
    </table>
  </div>
</div>
<script>
const statSent = {{stats.sent}};
const statOpened = {{stats.opened}};
const statClicked = {{stats.clicked}};
const statSubmitted = {{stats.submitted}};
const statCritical = {{stats.critical}};
const statHigh = {{stats.high}};
const statMedium = {{stats.medium}};
const statLow = {{stats.low}};

new Chart(document.getElementById('barChart'), {
  type: 'bar',
  data: {
    labels: ['Sent','Opened','Clicked','Submitted'],
    datasets: [
      { label: 'Count', data: [statSent, statOpened, statClicked, statSubmitted], backgroundColor: ['#28A745','#F59E0B','#FF0000','#8B0000'], borderRadius: 8, barThickness: 42 },
      { type: 'line', label: 'Trend', data: [statSent, statOpened, statClicked, statSubmitted], borderColor: '#003133', borderDash: [5,4], pointBackgroundColor: '#003133', tension: .35, fill: false }
    ]
  },
  options: { responsive:true, maintainAspectRatio:false, plugins:{legend:{position:'bottom'}}, scales:{y:{beginAtZero:true, ticks:{precision:0}}, x:{grid:{display:false}}} }
});
new Chart(document.getElementById('donutChart'), {
  type: 'doughnut',
  data: {
    labels: ['Critical','High','Medium','Low'],
    datasets: [{ data: [statCritical, statHigh, statMedium, statLow], backgroundColor: ['#8B0000','#FF0000','#F59E0B','#28A745'], borderColor:'#fff', borderWidth:3 }]
  },
  options: { responsive:true, maintainAspectRatio:false, cutout:'58%', plugins:{legend:{display:false}} }
});
function showPPPModal(){ document.getElementById('pppModal').style.display = 'flex'; }
function hidePPPModal(){ document.getElementById('pppModal').style.display = 'none'; }
function closePPPModal(e){ if(e.target.id === 'pppModal'){ hidePPPModal(); } }
document.addEventListener('keydown', function(e){ if(e.key === 'Escape'){ hidePPPModal(); } });
function changeCampaign(){ window.location='/?campaign_id=' + document.getElementById('campaignSel').value; }
function filterBy(type){ window.location='/?campaign_id=' + document.getElementById('campaignSel').value + '&filter=' + encodeURIComponent(type); }
function openReport(){ window.location='/report?campaign_id=' + document.getElementById('campaignSel').value; }
function searchTable(){
  const v = document.getElementById('search').value.toLowerCase();
  document.querySelectorAll('#tableBody tr').forEach(r => r.style.display = r.innerText.toLowerCase().includes(v) ? '' : 'none');
}
</script>
</body>
</html>"""
    return render_template_string(
        html,
        campaigns=campaigns,
        selected=selected,
        resolved_selected=resolved_selected,
        filter=filter_type,
        rows=rows,
        stats=stats,
        severity_level=severity_level,
        clean_time=clean_time,
        logo=LOGO_DATA_URI,
    )


@app.route("/report")
@login_required
def report():
    campaigns = get_campaigns()
    selected = request.args.get("campaign_id", "all")
    resolved_selected = resolve_campaign_id(selected)
    rows = get_campaign_rows(selected)
    stats = calculate_stats(rows)
    campaign_name = get_campaign_name(selected)
    username, is_admin = get_current_user()
    sb = sidebar_html(username, is_admin, active="report")

    html = """<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Report</title>""" + BASE_CSS + """</head>
<body>""" + sb + """
<div class="main">
  <div class="topbar">
    <div class="topbar-title-row"><div><h2>Phishing Campaign Report</h2><p>Comprehensive phishing campaign analysis</p></div></div>
    <a class="btn btn-primary" href="/download-report/{{resolved_selected}}">⬇ Download PDF</a>
  </div>
  <div class="panel">
    <div class="panel-header"><h3>Report Configuration</h3></div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:18px">
      <div><label><b>Campaign</b></label><br>
        <select onchange="window.location='/report?campaign_id='+this.value">
          <option value="all" {% if resolved_selected == 'all' %}selected{% endif %}>All Campaigns</option>
          <option value="recent" {% if selected == 'recent' %}selected{% endif %}>Recent Campaign</option>
          {% for c in campaigns %}<option value="{{c[0]}}" {% if resolved_selected == c[0]|string %}selected{% endif %}>{{c[1]}}</option>{% endfor %}
        </select>
      </div>
      <div><label><b>Status</b></label><br><span class="badge low">In Progress</span></div>
    </div>
    <p><b>Campaign:</b> {{campaign_name}}</p><br>
    <table>
      <thead><tr><th>Metric</th><th>Count</th></tr></thead>
      <tbody>
        <tr><td>Emails Sent</td><td><b>{{stats.sent}}</b></td></tr>
        <tr><td>Emails Opened</td><td><b>{{stats.opened}}</b></td></tr>
        <tr><td>Links Clicked</td><td><b>{{stats.clicked}}</b></td></tr>
        <tr><td>Submitted Data</td><td><b>{{stats.submitted}}</b></td></tr>
        <tr><td>Total Failures</td><td><b>{{stats.total_failures}}</b></td></tr>
        <tr><td>Total Emails Delivered</td><td><b>{{stats.total_delivered}}</b></td></tr>
        <tr><td>Phish-Prone Rate</td><td><b>{{stats.prone}}%</b></td></tr>
      </tbody>
    </table><br><br>
    <h3>Recipient Results</h3><br>
    <table>
      <thead><tr><th>#</th><th>Time</th><th>Name</th><th>Email</th><th>Event</th><th>Severity</th></tr></thead>
      <tbody>
      {% for r in rows %}{% set sev=severity_level(r[4]) %}
        <tr><td>{{loop.index}}</td><td>{{clean_time(r[5])}}</td><td>{{(r[1] ~ ' ' ~ r[2]).strip() or 'N/A'}}</td><td>{{r[3]}}</td><td>{{r[4]}}</td><td><span class="badge {{sev|lower}}">{{sev}}</span></td></tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
</div>
</body></html>"""
    return render_template_string(
        html,
        campaigns=campaigns,
        selected=selected,
        resolved_selected=resolved_selected,
        campaign_name=campaign_name,
        rows=rows,
        stats=stats,
        severity_level=severity_level,
        clean_time=clean_time,
        logo=LOGO_DATA_URI,
    )




def _pdf_logo(width=155, height=42):
    """Load Adamsbridge logo for PDF without stretching.
    Priority:
    1) local PNG/JPG file from PDF_LOGO_LOCAL_PATH
    2) SVG URL converted using svglib if installed
    3) raster URL
    4) text fallback
    """
    try:
        if os.path.exists(PDF_LOGO_LOCAL_PATH):
            img = Image(PDF_LOGO_LOCAL_PATH)
            ratio = min(width / float(img.imageWidth), height / float(img.imageHeight))
            img.drawWidth = img.imageWidth * ratio
            img.drawHeight = img.imageHeight * ratio
            return img
    except Exception:
        pass

    try:
        with urllib.request.urlopen(LOGO_DATA_URI, timeout=5) as response:
            raw = response.read()

        if LOGO_DATA_URI.lower().endswith('.svg') or raw[:100].lstrip().startswith(b'<svg'):
            try:
                from svglib.svglib import svg2rlg
                from reportlab.graphics.shapes import Drawing
                with tempfile.NamedTemporaryFile(delete=False, suffix='.svg') as tmp:
                    tmp.write(raw)
                    tmp_path = tmp.name
                drawing = svg2rlg(tmp_path)
                os.unlink(tmp_path)
                if drawing:
                    scale = min(width / float(drawing.width), height / float(drawing.height))
                    drawing.width = drawing.width * scale
                    drawing.height = drawing.height * scale
                    drawing.scale(scale, scale)
                    return drawing
            except Exception:
                return None

        data = BytesIO(raw)
        img = Image(data)
        ratio = min(width / float(img.imageWidth), height / float(img.imageHeight))
        img.drawWidth = img.imageWidth * ratio
        img.drawHeight = img.imageHeight * ratio
        return img
    except Exception:
        return None


def add_pdf_header(story, styles, title, subtitle=""):
    logo = _pdf_logo()
    title_style = ParagraphStyle(
        "PdfHeaderTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=17,
        leading=21,
        textColor=colors.white,
        alignment=2,
        spaceAfter=4,
    )
    sub_style = ParagraphStyle(
        "PdfHeaderSub",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor(ACCENT_COLOR),
        alignment=2,
    )
    fallback_logo = Paragraph("<font color='#003133'><b>adams</b>bridge</font><font color='#F5A94F'> ●</font>", styles["Heading2"])
    left = logo if logo else fallback_logo
    right = Paragraph(f"<b>{title}</b><br/><font color='{ACCENT_COLOR}' size='8'>{subtitle}</font>", title_style)
    header = Table([[left, right]], colWidths=[190, 545], rowHeights=[58])
    header.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), colors.white),
        ("BACKGROUND", (1, 0), (1, 0), colors.HexColor(PRIMARY_COLOR)),
        ("BOX", (0, 0), (-1, -1), 1.6, colors.HexColor(ACCENT_COLOR)),
        ("LINEBELOW", (0, 0), (-1, -1), 2, colors.HexColor(PRIMARY_COLOR)),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (0, 0), "CENTER"),
        ("ALIGN", (1, 0), (1, 0), "RIGHT"),
        ("LEFTPADDING", (0, 0), (0, 0), 12),
        ("RIGHTPADDING", (0, 0), (0, 0), 12),
        ("LEFTPADDING", (1, 0), (1, 0), 18),
        ("RIGHTPADDING", (1, 0), (1, 0), 18),
    ]))
    story.append(header)
    story.append(Spacer(1, 14))

def add_summary_cards(story, items):
    data = []
    row = []
    for label, value, color_hex in items:
        row.append(Paragraph(f"<font color='{color_hex}'><b>{value}</b></font><br/><font size='8'>{label}</font>", getSampleStyleSheet()["Normal"]))
    data.append(row)
    table = Table(data, colWidths=[147] * len(items), rowHeights=[48])
    style = TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#D8E0E5")),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FBFB")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor(ACCENT_COLOR)),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("PADDING", (0, 0), (-1, -1), 10),
    ])
    for idx, (_, _, color_hex) in enumerate(items):
        style.add("LINEABOVE", (idx, 0), (idx, 0), 3, colors.HexColor(color_hex))
    table.setStyle(style)
    story.append(table)
    story.append(Spacer(1, 14))


@app.route("/download-report/<campaign_id>")
@login_required
def download_report(campaign_id):
    """Download PDF only: professional portrait report.

    Dashboard/report web UI is unchanged. PDF result severity is only:
    High = clicked, Medium = opened, Low = sent/no risky action.
    Submitted Data/Critical is ignored in this PDF report.
    """
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.utils import ImageReader
    from reportlab.lib import colors
    from io import BytesIO
    import urllib.request
    import tempfile
    import os
    import math
    import base64

    campaign_id = resolve_campaign_id(campaign_id)
    campaign_name = get_campaign_name(campaign_id)
    generated_text = datetime.now(APP_TIMEZONE).strftime("%d-%m-%Y %I:%M:%S %p") + " " + APP_TIMEZONE_LABEL

    ADAMS_LOGO_URL = "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQ0SuEkshsjLKplBwSW40EE50zSVHoYIn33py8bVmY_oQ&s"

    # Embedded phishing awareness icon used in the PDF intro card.
    PHISH_ICON_B64 = """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"""

    def table_has_column(cur, table_name, column_name):
        try:
            cur.execute(f"PRAGMA table_info({table_name})")
            return column_name in [r[1] for r in cur.fetchall()]
        except Exception:
            return False

    def load_recipient_rows(selected_campaign_id):
        conn = get_db()
        cur = conn.cursor()

        campaign_created_col = None
        for col in ("created_date", "created_at", "created", "launch_date"):
            if table_has_column(cur, "campaigns", col):
                campaign_created_col = col
                break
        created_select = f"campaigns.{campaign_created_col}" if campaign_created_col else "NULL"

        params = []
        where = ""
        if selected_campaign_id != "all":
            where = "WHERE results.campaign_id = ?"
            params.append(selected_campaign_id)

        q = f"""
        SELECT
            COALESCE(results.email, '') AS email,
            COALESCE(results.campaign_id, '') AS campaign_id,
            COALESCE(campaigns.name, 'Unknown Campaign') AS campaign_name,
            {created_select} AS created_date
        FROM results
        LEFT JOIN campaigns ON results.campaign_id = campaigns.id
        {where}
        ORDER BY results.campaign_id DESC, LOWER(results.email)
        """
        try:
            cur.execute(q, params)
            base_rows = cur.fetchall()
        except Exception:
            base_rows = []

        output = []
        seen = set()
        for email, cid, cname, created_date in base_rows:
            email = (email or "").strip()
            cid = str(cid or "")
            if not email:
                continue
            key = (cid, email.lower())
            if key in seen:
                continue
            seen.add(key)

            cur.execute("""
                SELECT message, time
                FROM events
                WHERE campaign_id = ?
                  AND LOWER(email) = LOWER(?)
                  AND message != 'Campaign Created'
                ORDER BY time ASC
            """, (cid, email))
            events = cur.fetchall()

            # PDF report ignores Submitted Data/Critical.
            sent = 1 if any(is_sent_event(e[0]) for e in events) else 0
            opened = 1 if any(is_opened_event(e[0]) for e in events) else 0
            clicked = 1 if any(is_clicked_event(e[0]) for e in events) else 0

            if clicked:
                severity = "High"
            elif opened:
                severity = "Medium"
            else:
                severity = "Low"

            display_created = clean_date(created_date)
            if display_created == "N/A" and events:
                display_created = clean_date(events[0][1])

            output.append({
                "email": email,
                "created_date": display_created,
                "sent": sent,
                "opened": opened,
                "clicked": clicked,
                "severity": severity,
            })
        conn.close()
        return output

    recipient_rows = load_recipient_rows(campaign_id)
    # Sort result table severity-wise: High first, then Medium, then Low.
    severity_rank = {"High": 1, "Medium": 2, "Low": 3}
    recipient_rows.sort(key=lambda r: (severity_rank.get(r.get("severity"), 3), str(r.get("created_date", "")), str(r.get("email", "")).lower()))
    sent_total = sum(r["sent"] for r in recipient_rows)
    opened_total = sum(r["opened"] for r in recipient_rows)
    clicked_total = sum(r["clicked"] for r in recipient_rows)
    ppp = round((clicked_total / sent_total) * 100, 2) if sent_total else 0


    # Embedded clicked-link icon used in the PDF KPI card.
    CLICK_ICON_B64 = """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"""

    safe_name = campaign_name.replace(" ", "_").replace("/", "_")
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    page_w, page_h = A4
    margin = 26

    PRIMARY = colors.HexColor("#003133")
    PRIMARY_2 = colors.HexColor("#004C4E")
    ACCENT = colors.HexColor("#F5A94F")
    GREEN = colors.HexColor("#22A646")
    ORANGE = colors.HexColor("#F59E0B")
    RED = colors.HexColor("#FF0000")
    LIGHT_BG = colors.HexColor("#F7FAFA")
    BORDER = colors.HexColor("#D8E0E5")
    TEXT = colors.HexColor("#003133")
    MUTED = colors.HexColor("#637381")
    LIGHT_RING = colors.HexColor("#E5E7EA")

    def get_logo_reader():
        try:
            if os.path.exists(PDF_LOGO_LOCAL_PATH):
                return ImageReader(PDF_LOGO_LOCAL_PATH)
        except Exception:
            pass
        try:
            with urllib.request.urlopen(ADAMS_LOGO_URL, timeout=6) as resp:
                raw = resp.read()
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".png")
            tmp.write(raw)
            tmp.close()
            return ImageReader(tmp.name)
        except Exception:
            return None

    logo_reader = get_logo_reader()

    def get_phish_icon_reader():
        try:
            return ImageReader(BytesIO(base64.b64decode(PHISH_ICON_B64)))
        except Exception:
            return None

    phish_icon_reader = get_phish_icon_reader()

    def get_click_icon_reader():
        try:
            return ImageReader(BytesIO(base64.b64decode(CLICK_ICON_B64)))
        except Exception:
            return None

    click_icon_reader = get_click_icon_reader()

    def draw_logo_right(x, y, max_w=160, max_h=46):
        if logo_reader:
            try:
                iw, ih = logo_reader.getSize()
                scale = min(max_w / iw, max_h / ih)
                dw, dh = iw * scale, ih * scale
                c.drawImage(logo_reader, x + (max_w - dw) / 2, y + (max_h - dh) / 2, dw, dh, mask="auto")
                return
            except Exception:
                pass
        c.setFont("Helvetica", 23)
        c.setFillColor(TEXT)
        c.drawCentredString(x + max_w / 2, y + 18, "adamsbridge")
        c.setFillColor(ACCENT)
        c.circle(x + max_w - 14, y + 25, 6, fill=1, stroke=0)

    def draw_header():
        header_y = page_h - 86
        header_h = 72
        full_w = page_w - (margin * 2)
        logo_w = 190
        logo_x = margin + full_w - logo_w
        slant_top_x = logo_x - 24
        slant_bottom_x = logo_x - 56

        # Outer orange border
        c.setFillColor(colors.white)
        c.setStrokeColor(ACCENT)
        c.setLineWidth(1.8)
        c.rect(margin, header_y, full_w, header_h, fill=1, stroke=1)

        # Green left header with clean right slant.
        green = c.beginPath()
        green.moveTo(margin, header_y)
        green.lineTo(slant_bottom_x, header_y)
        green.lineTo(slant_top_x, header_y + header_h)
        green.lineTo(margin, header_y + header_h)
        green.close()
        c.setFillColor(PRIMARY)
        c.drawPath(green, fill=1, stroke=0)

        # Slight darker diagonal shade only inside green area.
        shade = c.beginPath()
        shade.moveTo(slant_bottom_x - 26, header_y)
        shade.lineTo(slant_bottom_x, header_y)
        shade.lineTo(slant_top_x, header_y + header_h)
        shade.lineTo(slant_top_x - 26, header_y + header_h)
        shade.close()
        c.setFillColor(PRIMARY_2)
        c.drawPath(shade, fill=1, stroke=0)

        # White logo side.
        c.setFillColor(colors.white)
        c.rect(logo_x, header_y + 1, logo_w - 1, header_h - 2, fill=1, stroke=0)
        draw_logo_right(logo_x + 10, header_y + 14, logo_w - 20, 44)

        c.setFillColor(colors.white)
        c.setFont("Helvetica-Bold", 18)
        c.drawString(margin + 18, header_y + 46, "PHISHING CAMPAIGN REPORT")
        c.setFont("Helvetica", 8.1)
        c.drawString(margin + 18, header_y + 27, f"Generated: {generated_text}")
        c.drawString(margin + 18, header_y + 14, f"Campaign: {campaign_name}")

    def draw_wrapped_text(text, x, y, width, font="Helvetica", size=8.7, leading=11.5, color=colors.black, max_lines=None):
        c.setFont(font, size)
        c.setFillColor(color)
        words = str(text).split()
        line = ""
        lines_drawn = 0
        for word in words:
            test = (line + " " + word).strip()
            if c.stringWidth(test, font, size) <= width:
                line = test
            else:
                if max_lines and lines_drawn >= max_lines:
                    return y
                c.drawString(x, y, line)
                y -= leading
                lines_drawn += 1
                line = word
        if line and (not max_lines or lines_drawn < max_lines):
            c.drawString(x, y, line)
            y -= leading
        return y

    def draw_donut(cx, cy, radius, percent, color):
        ring = 14
        c.setFillColor(LIGHT_RING)
        c.circle(cx, cy, radius, fill=1, stroke=0)
        c.setFillColor(color)
        pct = max(0, min(percent, 100))
        if pct > 0:
            # ReportLab wedge draws clean ring segment; start at top.
            c.wedge(cx - radius, cy - radius, cx + radius, cy + radius, 90, -360 * pct / 100.0, fill=1, stroke=0)
        c.setFillColor(colors.white)
        c.circle(cx, cy, radius - ring, fill=1, stroke=0)

    def icon_envelope(cx, cy):
        c.setStrokeColor(colors.white)
        c.setLineWidth(2.1)
        w, h = 24, 16
        x, y = cx - w / 2, cy - h / 2
        c.rect(x, y, w, h, fill=0, stroke=1)
        c.line(x, y + h, cx, cy)
        c.line(x + w, y + h, cx, cy)
        c.line(x, y, cx, cy)
        c.line(x + w, y, cx, cy)

    def icon_opened(cx, cy):
        c.setStrokeColor(colors.white)
        c.setLineWidth(2.1)
        w, h = 25, 15
        x, y = cx - w / 2, cy - h / 2 - 3
        # envelope body
        c.rect(x, y, w, h, fill=0, stroke=1)
        # open flap
        c.line(x, y + h, cx, y + h + 9)
        c.line(cx, y + h + 9, x + w, y + h)
        c.line(x, y + h, cx, y + 5)
        c.line(x + w, y + h, cx, y + 5)

    def icon_cursor(cx, cy):
        # Fallback mouse cursor/arrow icon for Clicked Link card.
        c.setStrokeColor(colors.white)
        c.setFillColor(colors.white)
        c.setLineWidth(1.8)
        p = c.beginPath()
        p.moveTo(cx - 8, cy + 16)
        p.lineTo(cx - 5, cy - 15)
        p.lineTo(cx + 13, cy + 1)
        p.lineTo(cx + 5, cy + 3)
        p.lineTo(cx + 11, cy - 10)
        p.lineTo(cx + 5, cy - 13)
        p.lineTo(cx - 1, cy + 1)
        p.close()
        c.drawPath(p, fill=0, stroke=1)

    def draw_click_link_image(x, y, size):
        # User requested clicked-link image. Keep it centered and do not overlap the text.
        if click_icon_reader:
            try:
                c.drawImage(click_icon_reader, x, y, size, size, preserveAspectRatio=True, mask="auto")
                return
            except Exception:
                pass
        c.setFillColor(RED)
        c.circle(x + size / 2, y + size / 2, size / 2, fill=1, stroke=0)
        icon_cursor(x + size / 2, y + size / 2)

    def draw_shield_icon(cx, cy):
        c.setStrokeColor(colors.white)
        c.setLineWidth(2.2)
        p = c.beginPath()
        p.moveTo(cx, cy + 22)
        p.lineTo(cx + 18, cy + 14)
        p.lineTo(cx + 15, cy - 8)
        p.curveTo(cx + 12, cy - 18, cx + 4, cy - 24, cx, cy - 27)
        p.curveTo(cx - 4, cy - 24, cx - 12, cy - 18, cx - 15, cy - 8)
        p.lineTo(cx - 18, cy + 14)
        p.close()
        c.drawPath(p, fill=0, stroke=1)
        # small check inside shield
        c.line(cx - 8, cy - 1, cx - 2, cy - 8)
        c.line(cx - 2, cy - 8, cx + 10, cy + 6)

    def draw_phish_image_icon(x, y, size):
        # Better intro logo: use the phishing alert image instead of tick/shield.
        if phish_icon_reader:
            try:
                c.drawImage(phish_icon_reader, x, y, size, size, preserveAspectRatio=True, mask="auto")
                return
            except Exception:
                pass
        # fallback simple phishing hook symbol
        c.setFillColor(RED)
        c.circle(x + size / 2, y + size / 2, size / 2, fill=1, stroke=0)
        c.setStrokeColor(colors.white)
        c.setLineWidth(3)
        c.arc(x + 18, y + 16, x + size - 14, y + size - 10, 210, 245)
        c.setFillColor(colors.white)
        c.circle(x + size - 18, y + size - 14, 4, fill=1, stroke=0)

    def draw_kpi_card(x, y, w, h, title, value, color, note, icon_type):
        # KPI card alignment fixed: icon, count, title and note get enough breathing space.
        c.setFillColor(colors.white)
        c.roundRect(x, y, w, h, 7, fill=1, stroke=0)
        c.setStrokeColor(BORDER)
        c.setLineWidth(1.1)
        c.roundRect(x, y, w, h, 7, fill=0, stroke=1)

        icon_cx = x + 36
        icon_cy = y + h / 2
        if icon_type == "clicked":
            # Clicked-link image is kept fully inside the card and away from text.
            draw_click_link_image(x + 13, y + (h - 50) / 2, 50)
        else:
            c.setFillColor(color)
            c.circle(icon_cx, icon_cy, 22, fill=1, stroke=0)
            if icon_type == "sent":
                icon_envelope(icon_cx, icon_cy)
            elif icon_type == "opened":
                icon_opened(icon_cx, icon_cy)

        text_x = x + 76
        c.setFillColor(color)
        c.setFont("Helvetica-Bold", 23)
        c.drawString(text_x, y + h - 27, str(value))
        c.setFillColor(TEXT)
        c.setFont("Helvetica-Bold", 9.6)
        c.drawString(text_x, y + h - 44, title)
        c.setFillColor(MUTED)
        c.setFont("Helvetica", 6.7)
        c.drawString(text_x, y + 13, note)

    def draw_top_section():
        top_y = page_h - 118
        box_h = 132
        gap = 12
        right_w = 198
        left_w = page_w - (margin * 2) - right_w - gap

        # Intro card - kept same height as PPP card, with clean gap between both boxes.
        c.setFillColor(LIGHT_BG)
        c.roundRect(margin, top_y - box_h, left_w, box_h, 8, fill=1, stroke=0)
        c.setStrokeColor(BORDER)
        c.setLineWidth(1.1)
        c.roundRect(margin, top_y - box_h, left_w, box_h, 8, fill=0, stroke=1)

        icon_size = 70
        draw_phish_image_icon(margin + 20, top_y - 95, icon_size)

        text_x = margin + 108
        c.setFillColor(TEXT)
        c.setFont("Helvetica-Bold", 15.4)
        c.drawString(text_x, top_y - 39, "INTERNAL PHISHING")
        c.drawString(text_x, top_y - 59, "AWARENESS INITIATIVE")
        desc = "Internal phishing awareness initiative by Adamsbridge to help employees identify phishing emails, suspicious links, and credential harvesting attempts."
        draw_wrapped_text(desc, text_x, top_y - 82, left_w - 130, size=7.7, leading=9.6, color=colors.HexColor("#263238"), max_lines=3)
        c.setFillColor(TEXT)
        c.setFont("Helvetica-Bold", 8.4)
        c.drawString(text_x, top_y - 117, "Stay alert. Stay secure.")

        # Phish-prone card: donut is centered, larger, and the bottom label has its own space.
        px = margin + left_w + gap
        c.setFillColor(colors.white)
        c.roundRect(px, top_y - box_h, right_w, box_h, 8, fill=1, stroke=0)
        c.setStrokeColor(BORDER)
        c.setLineWidth(1.1)
        c.roundRect(px, top_y - box_h, right_w, box_h, 8, fill=0, stroke=1)
        c.setFillColor(TEXT)
        c.setFont("Helvetica-Bold", 9.8)
        c.drawCentredString(px + right_w / 2, top_y - 20, "PHISH-PRONE")
        c.drawCentredString(px + right_w / 2, top_y - 34, "PERCENTAGE")

        donut_cx = px + right_w / 2
        donut_cy = top_y - 77
        draw_donut(donut_cx, donut_cy, 35, ppp, RED)
        c.setFillColor(RED)
        c.setFont("Helvetica-Bold", 11.8)
        c.drawCentredString(donut_cx, donut_cy + -1, f"{ppp}%")
        c.setFillColor(TEXT)
        c.setFont("Helvetica-Bold", 6.8)


        # Divider and summary text kept below the donut, not touching the circle.
        c.setStrokeColor(BORDER)
        c.setLineWidth(0.8)
        c.line(px + 28, top_y - 116, px + right_w - 28, top_y - 116)
        c.setFillColor(colors.HexColor("#111827"))
        c.setFont("Helvetica", 8.8)
        c.drawCentredString(donut_cx, top_y - 128, f"{clicked_total} Clicked / {sent_total} Sent")

        # KPI cards - same width, proper gaps, no touching between boxes.
        card_h = 70
        card_y = top_y - box_h - card_h - 14
        card_gap = 8
        card_w = (page_w - (margin * 2) - (card_gap * 2)) / 3
        draw_kpi_card(margin, card_y, card_w, card_h, "EMAILS SENT", sent_total, GREEN, "Total emails successfully sent", "sent")
        draw_kpi_card(margin + card_w + card_gap, card_y, card_w, card_h, "EMAILS OPENED", opened_total, ORANGE, "Total emails opened by users", "opened")
        draw_kpi_card(margin + (card_w + card_gap) * 2, card_y, card_w, card_h, "CLICKED LINK", clicked_total, RED, "Total users clicked the link", "clicked")
        return card_y - 34

    def severity_color(sev):
        if sev == "High":
            return RED
        if sev == "Medium":
            return ORANGE
        return GREEN

    def draw_table_header(y):
        c.setFillColor(TEXT)
        c.setFont("Helvetica-Bold", 10)
        c.drawString(margin, y + 13, f"Recipient Results: {len(recipient_rows)}")
        y -= 8
        col_widths = [32, 185, 72, 50, 55, 65, 84]
        headers = ["S.No", "Email", "Created Date", "Sent", "Opened", "Clicked", "Severity"]
        x = margin
        c.setFillColor(PRIMARY)
        c.rect(x, y - 18, sum(col_widths), 18, fill=1, stroke=0)
        c.setStrokeColor(BORDER)
        c.setLineWidth(0.5)
        c.setFont("Helvetica-Bold", 7.5)
        c.setFillColor(colors.white)
        for h, w in zip(headers, col_widths):
            c.rect(x, y - 18, w, 18, fill=0, stroke=1)
            c.drawCentredString(x + w / 2, y - 12, h)
            x += w
        return y - 18, col_widths

    def draw_recipient_table(start_y):
        y, col_widths = draw_table_header(start_y)
        row_h = 16
        c.setFont("Helvetica", 7.3)
        for idx, r in enumerate(recipient_rows, 1):
            if y - row_h < 48:
                draw_footer()
                c.showPage()
                draw_header()
                y, col_widths = draw_table_header(page_h - 115)
            x = margin
            c.setFillColor(colors.white if idx % 2 else colors.HexColor("#F9FAFA"))
            c.rect(x, y - row_h, sum(col_widths), row_h, fill=1, stroke=0)
            values = [idx, r["email"], r["created_date"], r["sent"], r["opened"], r["clicked"], r["severity"]]
            for col_i, (val, w) in enumerate(zip(values, col_widths)):
                c.setStrokeColor(BORDER)
                c.rect(x, y - row_h, w, row_h, fill=0, stroke=1)
                if col_i == 6:
                    sev = str(val)
                    c.setFillColor(severity_color(sev))
                    c.rect(x, y - row_h, w, row_h, fill=1, stroke=0)
                    c.setFillColor(colors.white if sev != "Medium" else colors.black)
                    c.setFont("Helvetica-Bold", 7.2)
                    c.drawCentredString(x + w / 2, y - 11, sev)
                    c.setFont("Helvetica", 7.3)
                else:
                    c.setFillColor(colors.black)
                    text = str(val)
                    if col_i == 1 and len(text) > 33:
                        text = text[:30] + "..."
                    if col_i in (0, 3, 4, 5):
                        c.drawCentredString(x + w / 2, y - 11, text)
                    else:
                        c.drawString(x + 4, y - 11, text)
                x += w
            y -= row_h
        return y

    def draw_footer():
        c.setStrokeColor(colors.HexColor("#263238"))
        c.line(margin, 35, page_w - margin, 35)
        c.setFillColor(TEXT)
        c.setFont("Helvetica-Bold", 8)
        c.drawString(margin, 22, "Security is everyone's responsibility. Think before you click.")
        c.setFont("Helvetica", 7.5)
        c.drawRightString(page_w - margin, 22, "Report generated by Adamsbridge Security Team")
        c.setFillColor(PRIMARY)
        c.rect(0, 0, page_w, 6, fill=1, stroke=0)

    draw_header()
    table_start_y = draw_top_section()
    draw_recipient_table(table_start_y)
    draw_footer()
    c.save()
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"{safe_name}_phishing_report.pdf", mimetype="application/pdf")


# =========================
# TRAINING MONITORING
# =========================
def ensure_training_status_db():
    """Create/update training DB columns used for full monitoring."""
    os.makedirs(os.path.dirname(TRAINING_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(TRAINING_DB_PATH)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS training_status (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        uid TEXT UNIQUE,
        campaign_id TEXT,
        campaign_name TEXT,
        first_name TEXT,
        last_name TEXT,
        full_name TEXT,
        email TEXT,
        status TEXT DEFAULT 'Pending',
        video_started_at TIMESTAMP,
        completed_at TIMESTAMP,
        video_seconds_watched REAL DEFAULT 0,
        video_total_seconds REAL DEFAULT 0,
        video_progress INTEGER DEFAULT 0,
        last_activity_at TIMESTAMP,
        certificate_downloaded INTEGER DEFAULT 0,
        certificate_downloaded_at TIMESTAMP
    )
    """)
    cur.execute("PRAGMA table_info(training_status)")
    cols = {r[1] for r in cur.fetchall()}
    add_cols = {
        "campaign_id": "TEXT",
        "campaign_name": "TEXT",
        "first_name": "TEXT",
        "last_name": "TEXT",
        "full_name": "TEXT",
        "email": "TEXT",
        "status": "TEXT DEFAULT 'Pending'",
        "video_started_at": "TIMESTAMP",
        "completed_at": "TIMESTAMP",
        "video_seconds_watched": "REAL DEFAULT 0",
        "video_total_seconds": "REAL DEFAULT 0",
        "video_progress": "INTEGER DEFAULT 0",
        "last_activity_at": "TIMESTAMP",
        "certificate_downloaded": "INTEGER DEFAULT 0",
        "certificate_downloaded_at": "TIMESTAMP",
    }
    for col, typ in add_cols.items():
        if col not in cols:
            cur.execute(f"ALTER TABLE training_status ADD COLUMN {col} {typ}")
    conn.commit()
    conn.close()


def upsert_training_status(uid, status="Pending", mark_certificate=False, progress=None, watched_seconds=None, total_seconds=None):
    """Insert/update training monitoring in TRAINING_DB_PATH.

    This keeps dashboard and training page using the same DB, so user start/progress/completion
    is visible immediately in Training Users.
    """
    ensure_training_status_db()
    user = get_abphish_user_by_uid(uid)
    now = app_now_db()
    first = user.get("first_name") or "User"
    last = user.get("last_name") or ""
    full_name = (first + " " + last).strip() or user.get("email") or "User"

    try:
        progress_int = int(float(progress)) if progress is not None else None
    except Exception:
        progress_int = None
    if progress_int is not None:
        progress_int = max(0, min(100, progress_int))

    try:
        watched_val = float(watched_seconds) if watched_seconds is not None else None
    except Exception:
        watched_val = None
    try:
        total_val = float(total_seconds) if total_seconds is not None else None
    except Exception:
        total_val = None

    conn = sqlite3.connect(TRAINING_DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, status, video_progress FROM training_status WHERE uid=?", (uid,))
    exists = cur.fetchone()

    if not exists:
        cur.execute("""
        INSERT INTO training_status
        (uid, campaign_id, campaign_name, first_name, last_name, full_name, email, status,
         video_started_at, completed_at, video_seconds_watched, video_total_seconds, video_progress,
         last_activity_at, certificate_downloaded, certificate_downloaded_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            uid, user.get("campaign_id", ""), user.get("campaign_name", "Unknown Campaign"),
            first, last, full_name, user.get("email", "Unknown"),
            "Completed" if status == "Completed" else "Pending",
            now,
            now if status == "Completed" else None,
            watched_val or 0,
            total_val or 0,
            100 if status == "Completed" else (progress_int or 0),
            now,
            1 if mark_certificate else 0,
            now if mark_certificate else None,
        ))
    else:
        # Never downgrade a completed user back to pending.
        existing_status = exists[1] or "Pending"
        final_status = "Completed" if status == "Completed" or existing_status == "Completed" else "Pending"
        final_progress = 100 if final_status == "Completed" else None
        if final_progress is None and progress_int is not None:
            final_progress = max(int(exists[2] or 0), progress_int)

        sets = [
            "campaign_id=?", "campaign_name=?", "first_name=?", "last_name=?", "full_name=?", "email=?",
            "status=?", "video_started_at=COALESCE(video_started_at, ?)", "last_activity_at=?"
        ]
        vals = [
            user.get("campaign_id", ""), user.get("campaign_name", "Unknown Campaign"), first, last,
            full_name, user.get("email", "Unknown"), final_status, now, now
        ]
        if status == "Completed":
            sets.append("completed_at=COALESCE(completed_at, ?)")
            vals.append(now)
        if watched_val is not None:
            sets.append("video_seconds_watched=MAX(COALESCE(video_seconds_watched,0), ?)")
            vals.append(watched_val)
        if total_val is not None and total_val > 0:
            sets.append("video_total_seconds=MAX(COALESCE(video_total_seconds,0), ?)")
            vals.append(total_val)
        if final_progress is not None:
            sets.append("video_progress=MAX(COALESCE(video_progress,0), ?)")
            vals.append(final_progress)
        if mark_certificate:
            sets.append("certificate_downloaded=1")
            sets.append("certificate_downloaded_at=COALESCE(certificate_downloaded_at, ?)")
            vals.append(now)
        vals.append(uid)
        cur.execute(f"UPDATE training_status SET {', '.join(sets)} WHERE uid=?", vals)

    conn.commit()
    conn.close()
    return user


@app.route("/training")
def training_page():
    uid = request.args.get("uid", "").strip()
    if not uid:
        return "Invalid training link. UID missing.", 400

    user = upsert_training_status(uid, status="Pending", progress=0, watched_seconds=0, total_seconds=0)
    full_name = (user["first_name"] + " " + user["last_name"]).strip()
    if not full_name or full_name == "User":
        full_name = user["email"] if user["email"] != "Unknown" else "User"

    html = """<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Phishing Awareness Training</title>
<style>
body { font-family:'Segoe UI',Arial,sans-serif; background:#f4f7f8; color:#003133; margin:0; padding:30px; }
.training-box { max-width:900px; margin:auto; background:white; border-radius:14px; padding:34px; box-shadow:0 4px 22px rgba(0,0,0,.12); text-align:center; }
h1 { color:#8B0000; margin-bottom:10px; }
video { width:100%; max-width:760px; border-radius:12px; margin-top:20px; background:#000; }
.status { margin-top:18px; font-weight:800; color:#F59E0B; }
.note { background:#fff7e8; border-left:4px solid #F5A94F; padding:14px; margin:20px 0; text-align:left; border-radius:8px; }
.progress-wrap { width:100%; max-width:760px; height:14px; background:#e8edf0; border-radius:20px; margin:18px auto 6px; overflow:hidden; }
.progress-bar { height:14px; width:0%; background:#28A745; transition:width .2s ease; }
.progress-text { font-size:13px; font-weight:800; color:#667785; }
</style>
</head>
<body>
<div class="training-box">
  <h1>You clicked a simulated phishing link</h1>
  <p>Hello <b>{{full_name}}</b>, this was part of an authorized phishing awareness exercise.</p>
  <div class="note">Please watch the full awareness video. Your watch progress and completion status will update automatically in the dashboard.</div>
  <video id="trainingVideo" controls controlsList="nodownload">
    <source src="/static/awareness.mp4" type="video/mp4">
    Your browser does not support video playback.
  </video>
  <div class="progress-wrap"><div id="progressBar" class="progress-bar"></div></div>
  <div id="progressText" class="progress-text">Watched: 0%</div>
  <p id="status" class="status">Training video pending...</p>
</div>
<script>
const uid = "{{uid}}";
const video = document.getElementById("trainingVideo");
const progressBar = document.getElementById("progressBar");
const progressText = document.getElementById("progressText");
let completedSent = false;
let lastSentAt = 0;

function sendProgress(force=false){
  const total = isFinite(video.duration) ? video.duration : 0;
  const watched = isFinite(video.currentTime) ? video.currentTime : 0;
  const percent = total > 0 ? Math.min(100, Math.round((watched / total) * 100)) : 0;
  progressBar.style.width = percent + "%";
  progressText.innerText = "Watched: " + percent + "%";

  const now = Date.now();
  if(!force && now - lastSentAt < 5000) return;
  lastSentAt = now;
  fetch("/training-progress", {
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body: JSON.stringify({uid:uid, progress:percent, watched_seconds:watched, total_seconds:total})
  }).catch(() => {});
}

video.addEventListener("play", () => sendProgress(true));
video.addEventListener("timeupdate", () => sendProgress(false));
video.addEventListener("pause", () => sendProgress(true));
video.addEventListener("ended", function(){
  if (completedSent) return;
  completedSent = true;
  sendProgress(true);
  fetch("/training-completed", {
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body: JSON.stringify({uid:uid, progress:100, watched_seconds:video.duration || video.currentTime || 0, total_seconds:video.duration || 0})
  })
  .then(res => res.json())
  .then(() => {
    progressBar.style.width = "100%";
    progressText.innerText = "Watched: 100%";
    document.getElementById("status").innerText = "You completed the phishing awareness video.";
    document.getElementById("status").style.color = "#28A745";
  })
  .catch(() => {
    document.getElementById("status").innerText = "Completed, but status update failed. Please contact IT/Security.";
    document.getElementById("status").style.color = "#EF1C25";
  });
});
</script>
</body>
</html>"""
    return render_template_string(html, uid=uid, full_name=full_name)


@app.route("/training-progress", methods=["POST"])
def training_progress():
    data = request.get_json(silent=True) or {}
    uid = str(data.get("uid", "")).strip()
    if not uid:
        return {"success": False, "error": "UID missing"}, 400
    upsert_training_status(
        uid,
        status="Pending",
        progress=data.get("progress"),
        watched_seconds=data.get("watched_seconds"),
        total_seconds=data.get("total_seconds"),
    )
    return {"success": True}


@app.route("/training-completed", methods=["POST"])
def training_completed():
    data = request.get_json(silent=True) or {}
    uid = str(data.get("uid", "")).strip()
    if not uid:
        return {"success": False, "error": "UID missing"}, 400
    upsert_training_status(
        uid,
        status="Completed",
        progress=100,
        watched_seconds=data.get("watched_seconds"),
        total_seconds=data.get("total_seconds"),
    )
    return {"success": True}


def seconds_to_mmss(value):
    try:
        sec = int(float(value or 0))
    except Exception:
        sec = 0
    return f"{sec // 60:02d}:{sec % 60:02d}"


def progress_class(value):
    """Green shade based on video watched percentage."""
    try:
        p = int(float(value or 0))
    except Exception:
        p = 0
    if p >= 100:
        return "p100"
    if p >= 66:
        return "p66"
    if p >= 33:
        return "p33"
    if p > 0:
        return "p1"
    return "p0"


def build_campaign_training_summary(users):
    summary = {}
    for u in users:
        cid = str(u.get("campaign_id") or "")
        cname = u.get("campaign_name") or "Unknown Campaign"
        if cid not in summary:
            summary[cid] = {
                "campaign_id": cid,
                "campaign_name": cname,
                "total": 0,
                "started": 0,
                "completed": 0,
                "pending": 0,
                "overdue": 0,
            }
        item = summary[cid]
        item["total"] += 1
        if u.get("video_started_at") and u.get("status") != "Completed":
            item["started"] += 1
        if u.get("status") == "Completed":
            item["completed"] += 1
        else:
            item["pending"] += 1
        if u.get("is_overdue") and u.get("status") != "Completed":
            item["overdue"] += 1
    return sorted(summary.values(), key=lambda x: (x["overdue"], x["pending"], x["total"]), reverse=True)


def get_training_user_rows(campaign_id="all", status_filter="all"):
    """Return users who started/clicked training with full video monitoring."""
    ensure_training_status_db()
    campaign_id = resolve_campaign_id(campaign_id)
    status_filter = status_filter or "all"

    def due_validity(started_or_clicked, status, completed_at=None):
        base_time = parse_app_datetime(started_or_clicked)
        completed_time = parse_app_datetime(completed_at)
        if status == "Completed":
            return "Completed", False, None, 0
        if not base_time:
            return "N/A", False, None, 0
        due = base_time + timedelta(days=3)
        is_overdue = datetime.now(APP_TIMEZONE) >= due and completed_time is None
        overdue_days = days_overdue_from(due) if is_overdue else 0
        return clean_time(due), is_overdue, due, overdue_days

    # 1) Load training page/progress records.
    training_rows = []
    training_by_uid = {}
    training_by_email_campaign = {}
    try:
        conn = sqlite3.connect(TRAINING_DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("""
        SELECT uid, campaign_id, campaign_name, first_name, last_name, full_name, email, status,
               video_started_at, completed_at, video_seconds_watched, video_total_seconds,
               video_progress, last_activity_at
        FROM training_status
        ORDER BY COALESCE(last_activity_at, video_started_at, completed_at) DESC
        """)
        raw_rows = cur.fetchall()
        conn.close()
    except Exception:
        raw_rows = []

    for row in raw_rows:
        data = dict(row)
        uid = str(data.get("uid") or "").strip()
        gp = get_abphish_user_by_uid(uid) if uid else {}
        row_campaign_id = str(data.get("campaign_id") or gp.get("campaign_id") or "")
        if campaign_id != "all" and row_campaign_id != str(campaign_id):
            continue
        first = data.get("first_name") or gp.get("first_name") or ""
        last = data.get("last_name") or gp.get("last_name") or ""
        full_name = data.get("full_name") or (first + " " + last).strip() or "User"
        email = data.get("email") or gp.get("email") or "N/A"
        status = "Completed" if data.get("status") == "Completed" else "Pending"
        video_started_at, completed_at = normalize_start_completed(data.get("video_started_at"), data.get("completed_at"))
        clicked_at = latest_event_time_for_uid_or_email(uid, email, row_campaign_id)
        base_time = video_started_at or clicked_at
        validity, is_overdue, due_at, overdue_days = due_validity(base_time, status, completed_at)
        progress = 100 if status == "Completed" else int(data.get("video_progress") or 0)
        watched = float(data.get("video_seconds_watched") or 0)
        total = float(data.get("video_total_seconds") or 0)
        item = {
            "campaign_id": row_campaign_id,
            "campaign_name": data.get("campaign_name") or gp.get("campaign_name") or "Unknown Campaign",
            "name": full_name,
            "email": email,
            "status": status,
            "video_started_at": video_started_at,
            "completed_at": completed_at,
            "clicked_at": clicked_at,
            "video_progress": progress,
            "video_seconds_watched": watched,
            "video_total_seconds": total,
            "watch_time": seconds_to_mmss(watched) + (" / " + seconds_to_mmss(total) if total else ""),
            "last_activity_at": data.get("last_activity_at") or video_started_at or clicked_at,
            "validity": validity,
            "due_at": due_at,
            "is_overdue": is_overdue,
            "overdue_days": overdue_days,
            "uid": uid,
        }
        training_rows.append(item)
        if uid:
            training_by_uid[uid] = item
        email_key = str(email or "").strip().lower()
        if email_key:
            training_by_email_campaign[(email_key, row_campaign_id)] = item

    # 2) Add clicked users who have not opened training page yet.
    clicked_rows = []
    try:
        conn = get_db()
        cur = conn.cursor()
        q = """
        SELECT COALESCE(campaigns.id,''), COALESCE(campaigns.name,'Unknown Campaign'),
               COALESCE(results.first_name,''), COALESCE(results.last_name,''),
               COALESCE(events.email,''), events.time, COALESCE(results.r_id,'')
        FROM events
        LEFT JOIN campaigns ON events.campaign_id = campaigns.id
        LEFT JOIN results ON events.email = results.email AND events.campaign_id = results.campaign_id
        WHERE events.message = 'Clicked Link'
        """
        params = []
        if campaign_id != "all":
            q += " AND events.campaign_id=?"
            params.append(campaign_id)
        q += " ORDER BY events.time DESC"
        cur.execute(q, params)
        events = cur.fetchall()
        conn.close()
    except Exception:
        events = []

    seen = set()
    for c in events:
        row_campaign_id = str(c[0] or "")
        email = str(c[4] or "N/A")
        email_key = email.strip().lower()
        uid = str(c[6] or "").strip()
        key = (email_key, row_campaign_id)
        if key in seen:
            continue
        seen.add(key)
        matched = training_by_uid.get(uid) if uid else None
        if not matched:
            matched = training_by_email_campaign.get((email_key, row_campaign_id))
        if matched:
            clicked_rows.append(matched)
            continue
        name = ((str(c[2] or "") + " " + str(c[3] or "")).strip()) or "User"
        clicked_at = c[5]
        validity, is_overdue, due_at, overdue_days = due_validity(clicked_at, "Pending", None)
        clicked_rows.append({
            "campaign_id": row_campaign_id,
            "campaign_name": c[1] or "Unknown Campaign",
            "name": name,
            "email": email,
            "status": "Pending",
            "video_started_at": None,
            "completed_at": None,
            "clicked_at": clicked_at,
            "video_progress": 0,
            "video_seconds_watched": 0,
            "video_total_seconds": 0,
            "watch_time": "00:00",
            "last_activity_at": clicked_at,
            "validity": validity,
            "due_at": due_at,
            "is_overdue": is_overdue,
            "overdue_days": overdue_days,
            "uid": uid,
        })

    # all means users who started training + clicked users (deduped), not campaign cards.
    merged = []
    merge_seen = set()
    for u in clicked_rows + training_rows:
        k = (str(u.get("uid") or ""), str(u.get("email") or "").lower(), str(u.get("campaign_id") or ""))
        if k in merge_seen:
            continue
        merge_seen.add(k)
        merged.append(u)

    if status_filter == "Completed":
        return [u for u in merged if u.get("status") == "Completed"]
    if status_filter == "Pending":
        return [u for u in merged if u.get("status") != "Completed"]
    if status_filter == "Started Training":
        return [u for u in merged if u.get("video_started_at") and u.get("status") != "Completed"]
    if status_filter == "Clicked Training":
        return merged
    if status_filter == "Overdue":
        return [u for u in merged if u.get("is_overdue") and u.get("status") != "Completed"]
    return merged


@app.route("/training-users")
@login_required
def training_users():
    username, is_admin = get_current_user()
    sb = sidebar_html(username, is_admin, active="training")

    selected = request.args.get("campaign_id", "all")
    resolved_selected = resolve_campaign_id(selected)
    status_param = request.args.get("status")
    status_filter = status_param or "all"
    view_mode = request.args.get("view", "users")

    campaigns = get_campaigns()
    all_users = get_training_user_rows(selected, "all")
    users = get_training_user_rows(selected, status_filter)
    campaign_summary = build_campaign_training_summary(all_users)

    total = len(all_users)
    completed = sum(1 for u in all_users if u["status"] == "Completed")
    pending = total - completed
    started = sum(1 for u in all_users if u.get("video_started_at") and u.get("status") != "Completed")
    overdue = len(get_training_user_rows(selected, "Overdue"))

    html = """<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Training Users</title>
""" + BASE_CSS + """
<style>
.progress-mini { width:120px; height:10px; background:#e8edf0; border-radius:12px; overflow:hidden; display:inline-block; vertical-align:middle; margin-right:7px; }
.progress-mini-bar { height:10px; border-radius:12px; transition:width .25s ease; display:block; min-width:0; }
.progress-mini-bar.p0 { background:#e8edf0; }
.progress-mini-bar.p1 { background:#d9f7e3; }
.progress-mini-bar.p33 { background:#a7e8bb; }
.progress-mini-bar.p66 { background:#5fd17c; }
.progress-mini-bar.p100 { background:#28A745; }
.progress-mini-text { font-weight:900; }
.progress-mini-text.p0 { color:#003133; }
.progress-mini-text.p1 { color:#1f8f3a; }
.progress-mini-text.p33 { color:#187a32; }
.progress-mini-text.p66 { color:#146c2e; }
.progress-mini-text.p100 { color:#0b6b2b; }
.campaign-row { cursor:pointer; }
.campaign-row:hover { background:#fff7e9 !important; }
.campaign-help { font-size:12px; color:#667785; font-weight:800; margin-top:6px; }
</style>
</head>
<body>
""" + sb + """
<div class="main">
  <div class="topbar">
    <div class="topbar-title-row">
      <div>
        <h2>Training Users</h2>
        <p>Campaign-wise phishing awareness training monitoring</p>
      </div>
    </div>
    <div class="topbar-right">
      <div>
        <select id="campaignSel" onchange="changeTrainingCampaign()">
          <option value="all" {% if resolved_selected == 'all' %}selected{% endif %}>All Campaigns</option>
          <option value="recent" {% if selected == 'recent' %}selected{% endif %}>Recent Campaign</option>
          {% for c in campaigns %}
          <option value="{{c[0]}}" {% if resolved_selected == c[0]|string %}selected{% endif %}>{{c[1]}}</option>
          {% endfor %}
        </select>
        <div class="campaign-help">Select/click one campaign to show only that campaign users</div>
      </div>
      <a class="btn btn-primary" href="/download-training-report?campaign_id={{selected}}&status={{status_filter}}">⬇ Download Report</a>
    </div>
  </div>

  <div class="filter-tabs">
    <a class="filter-tab all {% if status_filter == 'all' and view_mode == 'campaigns' %}active{% endif %}" href="/training-users?campaign_id={{selected}}&status=all&view=campaigns">
      <h1>{{total}}</h1><p>Clicked / Training Users</p>
    </a>
    <a class="filter-tab recent {% if status_filter == 'Started Training' %}active{% endif %}" href="/training-users?campaign_id={{selected}}&status=Started Training&view=users">
      <h1>{{started}}</h1><p>Started Training</p>
    </a>
    <a class="filter-tab completed {% if status_filter == 'Completed' %}active{% endif %}" href="/training-users?campaign_id={{selected}}&status=Completed&view=users">
      <h1>{{completed}}</h1><p>Video Completed</p>
    </a>
    <a class="filter-tab pending {% if status_filter == 'Pending' %}active{% endif %}" href="/training-users?campaign_id={{selected}}&status=Pending&view=users">
      <h1>{{pending}}</h1><p>Pending</p>
    </a>
    <a class="filter-tab overdue {% if status_filter == 'Overdue' %}active{% endif %}" href="/training-users?campaign_id={{selected}}&status=Overdue&view=users">
      <h1>{{overdue}}</h1><p>Not Completed &gt; 3 Days</p>
    </a>
  </div>

  <div class="panel">
    <div class="panel-header">
      <h3>User Training Monitoring {% if resolved_selected != 'all' %}<span style="font-size:13px;color:#667785">/ {{get_campaign_name(selected)}}</span>{% endif %}</h3>
      <div class="panel-actions">
        {% if resolved_selected != 'all' or status_param %}<a class="btn btn-small btn-outline" href="/training-users?campaign_id=all&status=all&view=campaigns">← Back</a>{% endif %}
        {% if status_param %}<a class="btn btn-small btn-gold" href="/training-users?campaign_id={{selected}}&status=all&view=users">Clear Filter</a>{% endif %}
        <div class="search-box"><input id="search" onkeyup="searchTable()" placeholder="🔍 Search users..."></div>
      </div>
    </div>

    {% if view_mode == 'campaigns' %}
    <table>
      <thead>
        <tr><th>#</th><th>Campaign Name</th><th>Clicked / Training Users</th><th>Started Training</th><th>Video Completed</th><th>Pending</th><th>Not Completed &gt; 3 Days</th></tr>
      </thead>
      <tbody>
      {% if campaign_summary %}
        {% for c in campaign_summary %}
        <tr class="campaign-row" onclick="window.location='/training-users?campaign_id={{c.campaign_id}}&status=all&view=users'">
          <td>{{loop.index}}</td><td><b>{{c.campaign_name}}</b></td><td>{{c.total}}</td><td><span class="badge info">{{c.started}}</span></td><td><span class="badge low">{{c.completed}}</span></td><td><span class="badge medium">{{c.pending}}</span></td><td><span class="badge overdue">{{c.overdue}}</span></td>
        </tr>
        {% endfor %}
      {% else %}
        <tr><td colspan="7" style="text-align:center;padding:35px;color:#777">No campaign training data found.</td></tr>
      {% endif %}
      </tbody>
    </table>
    {% else %}
    <table>
      <thead>
        <tr>
          <th>#</th>
          <th>Campaign Name</th>
          <th>Name</th>
          <th>Email</th>
          <th>Status</th>
          <th>Started / Clicked</th>
          <th>Video Watched</th>
          <th>Watch Time</th>
          <th>Completed At</th>
          <th>3 Days Status</th>
          <th>Overdue Days</th>
        </tr>
      </thead>
      <tbody id="tableBody">
      {% if users %}
        {% for u in users %}
        <tr>
          <td>{{loop.index}}</td>
          <td><b>{{u.campaign_name}}</b></td>
          <td><b>{{u.name}}</b></td>
          <td>{{u.email}}</td>
          <td>
            {% if u.status == 'Completed' %}<span class="badge low">Completed</span>
            {% elif u.video_started_at %}<span class="badge info">Started</span>
            {% else %}<span class="badge medium">Clicked</span>{% endif %}
          </td>
          <td>{% if u.video_started_at %}{{clean_time(u.video_started_at)}}{% else %}{{clean_time(u.clicked_at)}}{% endif %}</td>
          <td><span class="progress-mini"><span class="progress-mini-bar {{progress_class(u.video_progress)}}" style="width:{{u.video_progress}}%"></span></span><b class="progress-mini-text {{progress_class(u.video_progress)}}">{{u.video_progress}}%</b></td>
          <td>{{u.watch_time}}</td>
          <td>{{clean_time(u.completed_at)}}</td>
          <td>{% if u.status == 'Completed' %}<span class="badge low">Completed</span>{% elif u.is_overdue %}<span class="badge overdue">Expired</span>{% else %}<span class="badge info">Valid till {{clean_time(u.due_at)}}</span>{% endif %}</td>
          <td>{% if u.overdue_days %}{{u.overdue_days}} day(s){% else %}-{% endif %}</td>
        </tr>
        {% endfor %}
      {% else %}
        <tr><td colspan="11" style="text-align:center;padding:35px;color:#777">Select a campaign or wait until users click/start training.</td></tr>
      {% endif %}
      </tbody>
    </table>
    {% endif %}
  </div>
</div>

<script>
function changeTrainingCampaign(){
  window.location='/training-users?campaign_id=' + document.getElementById('campaignSel').value + '&status={{status_filter}}&view=users';
}
function searchTable(){
  const v = document.getElementById('search').value.toLowerCase();
  document.querySelectorAll('#tableBody tr').forEach(r => {
    r.style.display = r.innerText.toLowerCase().includes(v) ? '' : 'none';
  });
}
</script>
</body>
</html>
"""

    return render_template_string(
        html,
        users=users,
        total=total,
        completed=completed,
        pending=pending,
        started=started,
        campaigns=campaigns,
        selected=selected,
        resolved_selected=resolved_selected,
        status_filter=status_filter,
        status_param=status_param,
        view_mode=view_mode,
        campaign_summary=campaign_summary,
        progress_class=progress_class,
        overdue=overdue,
        clean_time=clean_time,
        get_campaign_name=get_campaign_name,
        logo=LOGO_DATA_URI
    )



@app.route("/download-training-report")
@login_required
def download_training_report():
    selected = request.args.get("campaign_id", "all")
    status_filter = request.args.get("status", "all")
    users = get_training_user_rows(selected, status_filter)
    campaign_name = get_campaign_name(selected)

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=20,
        leftMargin=20,
        topMargin=20,
        bottomMargin=20,
    )
    styles = getSampleStyleSheet()
    story = []

    title_style = ParagraphStyle(
        "OldTrainingTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=colors.white,
        alignment=1,
    )
    normal_small = ParagraphStyle(
        "TrainingSmall",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=6.2,
        leading=7.4,
        wordWrap="CJK",
    )
    normal_bold = ParagraphStyle(
        "TrainingBold",
        parent=normal_small,
        fontName="Helvetica-Bold",
    )
    white_bold = ParagraphStyle(
        "TrainingWhiteBold",
        parent=normal_small,
        fontName="Helvetica-Bold",
        textColor=colors.white,
    )

    # Old report style retained: simple title block + info table + result table.
    header = Table(
        [[Paragraph("ADAMSBRIDGE<br/>TRAINING USERS REPORT", title_style)]],
        colWidths=[545],
        rowHeights=[58],
    )
    header.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(PRIMARY_COLOR)),
        ("BOX", (0, 0), (-1, -1), 1.5, colors.HexColor(ACCENT_COLOR)),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(header)
    story.append(Spacer(1, 14))

    info_data = [
        [Paragraph("Campaign", normal_bold), Paragraph(campaign_name, normal_small)],
        [Paragraph("Filter", normal_bold), Paragraph(status_filter.title(), normal_small)],
        [Paragraph("Generated", normal_bold), Paragraph(datetime.now(APP_TIMEZONE).strftime("%d-%m-%Y %I:%M:%S %p") + " " + APP_TIMEZONE_LABEL, normal_small)],
    ]
    info_table = Table(info_data, colWidths=[150, 395], rowHeights=[18, 18, 18])
    info_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#CCCCCC")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F9F6F1")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.append(info_table)
    story.append(Spacer(1, 14))

    data = [[
        Paragraph("#", white_bold),
        Paragraph("Campaign", white_bold),
        Paragraph("Name", white_bold),
        Paragraph("Email", white_bold),
        Paragraph("Status", white_bold),
        Paragraph("Started", white_bold),
        Paragraph("Completed", white_bold),
    ]]
    for i, u in enumerate(users, 1):
        data.append([
            Paragraph(str(i), normal_small),
            Paragraph(str(u["campaign_name"] or "Unknown Campaign"), normal_small),
            Paragraph(str(u["name"] or "User"), normal_small),
            Paragraph(str(u["email"] or "Unknown"), normal_small),
            Paragraph(str(u["status"] or "Pending"), normal_bold),
            Paragraph(clean_time(u["video_started_at"]), normal_small),
            Paragraph(clean_time(u["completed_at"]), normal_small),
        ])

    table = Table(data, colWidths=[25, 105, 70, 145, 70, 65, 65], repeatRows=1)
    ts = TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(PRIMARY_COLOR)),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#CCCCCC")),
        ("PADDING", (0, 0), (-1, -1), 5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#FAFAFA")]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ])
    for row_index, u in enumerate(users, 1):
        color = LOW_COLOR if u["status"] == "Completed" else MEDIUM_COLOR
        ts.add("BACKGROUND", (4, row_index), (4, row_index), colors.HexColor(color))
        ts.add("TEXTCOLOR", (4, row_index), (4, row_index), colors.white)
    table.setStyle(ts)
    story.append(table)

    doc.build(story)
    buffer.seek(0)

    # Embedded clicked-link icon used in the PDF KPI card.
    CLICK_ICON_B64 = """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"""

    safe_name = campaign_name.replace(" ", "_").replace("/", "_")
    return send_file(buffer, as_attachment=True, download_name=f"{safe_name}_training_users_report.pdf", mimetype="application/pdf")


@app.route("/admin")
@admin_required
def admin_panel():
    conn = sqlite3.connect(AUTH_DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, username, email, permissions, is_active, created_at FROM sub_users ORDER BY created_at DESC")
    sub_users = cur.fetchall()
    cur.execute("SELECT username, ip_address, login_time, success FROM login_logs ORDER BY login_time DESC LIMIT 50")
    logs = cur.fetchall()
    cur.execute("""
        SELECT id, username, ip_address, user_agent, login_time, last_seen, is_admin
        FROM active_sessions
        WHERE is_active=1
        ORDER BY last_seen DESC
    """)
    active_sessions = cur.fetchall()
    conn.close()

    username, is_admin = get_current_user()
    sb = sidebar_html(username, is_admin, active="admin")
    html = """<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Admin</title>""" + BASE_CSS + """</head><body>""" + sb + """
<div class="main">
  <div class="topbar"><div><h2>Admin Panel</h2><p>Manage users and login activity</p></div></div>
  <div class="panel">
    <div class="panel-header"><h3>Create Sub-User</h3></div>
    <form method="POST" action="/admin/create-subuser">
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
        <div class="form-group"><label>Username</label><input name="username" required></div>
        <div class="form-group"><label>Email</label><input type="email" name="email" required></div>
        <div class="form-group"><label>Password</label><input type="password" name="password" required></div>
        <div class="form-group"><label>Confirm Password</label><input type="password" name="confirm_password" required></div>
        <div class="form-group"><label>Permissions</label><select name="permissions"><option value="view">View Only</option><option value="edit">Can Edit</option><option value="full">Full Access</option></select></div>
        <div class="form-group" style="display:flex;align-items:end"><button class="btn btn-primary" type="submit">Create Sub-User</button></div>
      </div>
    </form>
  </div>
  <div class="panel" style="margin-top:20px">
    <div class="panel-header"><h3>Sub Users</h3></div>
    <table><thead><tr><th>Username</th><th>Email</th><th>Permission</th><th>Status</th><th>Created</th><th>Action</th></tr></thead><tbody>
    {% for u in sub_users %}<tr><td>{{u[1]}}</td><td>{{u[2]}}</td><td><span class="permission-badge">{{u[3]}}</span></td><td>{{'Active' if u[4] else 'Inactive'}}</td><td>{{clean_time(u[5])}}</td><td><form method="POST" action="/admin/delete-subuser/{{u[0]}}"><button class="btn btn-danger" onclick="return confirm('Delete user?')">Delete</button></form></td></tr>{% endfor %}
    </tbody></table>
  </div>
  <div class="panel" style="margin-top:20px">
    <div class="panel-header"><h3>Currently Logged-in Users</h3></div>
    <table><thead><tr><th>Username</th><th>IP</th><th>Role</th><th>Login Time</th><th>Last Seen</th><th>Action</th></tr></thead><tbody>
    {% for a in active_sessions %}
    <tr>
      <td><b>{{a[1]}}</b></td><td>{{a[2]}}</td><td>{{'Admin' if a[6] else 'User'}}</td><td>{{clean_time(a[4])}}</td><td>{{clean_time(a[5])}}</td>
      <td><form method="POST" action="/admin/logout-session/{{a[0]}}"><button class="btn btn-danger btn-small" onclick="return confirm('Logout this user?')">Logout</button></form></td>
    </tr>
    {% endfor %}
    </tbody></table>
  </div>
  <div class="panel" style="margin-top:20px">
    <div class="panel-header"><h3>Login Activity</h3></div>
    <table><thead><tr><th>Username</th><th>IP</th><th>Time</th><th>Status</th></tr></thead><tbody>
    {% for l in logs %}<tr><td>{{l[0]}}</td><td>{{l[1]}}</td><td>{{clean_time(l[2])}}</td><td>{% if l[3] %}<span class="badge success">Success</span>{% else %}<span class="badge failed">Failed</span>{% endif %}</td></tr>{% endfor %}
    </tbody></table>
  </div>
</div></body></html>"""
    return render_template_string(html, sub_users=sub_users, logs=logs, active_sessions=active_sessions, clean_time=clean_time)


@app.route("/admin/create-subuser", methods=["POST"])
@admin_required
def create_subuser():
    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")
    permissions = request.form.get("permissions", "view")
    if not all([username, email, password]):
        return "Missing required fields", 400
    if password != confirm_password:
        return "Passwords do not match", 400
    conn = sqlite3.connect(AUTH_DB_PATH)
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO sub_users (parent_id, username, password_hash, email, permissions) VALUES (?, ?, ?, ?, ?)", (session["user_id"], username, hash_password(password), email, permissions))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return "Username already exists", 400
    conn.close()
    return redirect(url_for("admin_panel"))


@app.route("/admin/logout-session/<session_id>", methods=["POST"])
@admin_required
def logout_user_session(session_id):
    conn = sqlite3.connect(AUTH_DB_PATH) 
    cur = conn.cursor()
    cur.execute("UPDATE active_sessions SET is_active=0 WHERE id=?", (session_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin_panel"))


@app.route("/admin/delete-subuser/<sub_user_id>", methods=["POST"])
@admin_required
def delete_subuser(sub_user_id):
    conn = sqlite3.connect(AUTH_DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM sub_users WHERE id=?", (sub_user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin_panel"))


LOGIN_TEMPLATE = """<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Login</title>""" + BASE_CSS + """</head>
<body>
<div class="login-container">
  <div class="login-box">
    <div class="login-logo"><img src=""" + LOGO_DATA_URI + """" alt="Adamsbridge "></div>
    {% if error %}<div class="alert">{{error}}</div>{% endif %}
    <form method="POST">
      <div class="form-group"><label>Username</label><input name="username" required autofocus></div>
      <div class="form-group"><label>Password</label><input type="password" name="password" required></div>
      <button type="submit" class="btn btn-primary">Login</button>
    </form>
    
  </div>
</div>
</body></html>"""


if __name__ == "__main__":
    init_auth_db()
    app.run(host="0.0.0.0", port=PORT, debug=True)
