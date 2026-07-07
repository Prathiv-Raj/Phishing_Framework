from flask import Flask, request, render_template_string, jsonify, redirect, url_for, make_response, abort
import sqlite3
from datetime import datetime
import os
import secrets

app = Flask(__name__)

PORT = int(os.environ.get("PORT", "9090"))
DB_PATH = os.environ.get("TRAINING_DB_PATH", "training_status.db")
GOPHISH_DB_PATH = os.environ.get("GOPHISH_DB_PATH", "")
VIDEO_COUNT = 3

VIDEOS = [
    {"id": "video1", "title": "Video 1", "filename": "video1.mp4"},
    {"id": "video2", "title": "Video 2", "filename": "video2.mp4"},
    {"id": "video3", "title": "Video 3", "filename": "video3.mp4"},
]

PASS_SCORE = 8

QUIZ_QUESTIONS = [
    {"q":"What is Phishing?","options":{"A":"A type of fishing sport","B":"A cyberattack where criminals trick users into revealing sensitive information","C":"A software update process","D":"A method to speed up internet connection"},"answer":"B"},
    {"q":"Which of the following is a common sign of a phishing email?","options":{"A":"Email from a known colleague with proper grammar","B":"Urgent language pressuring you to act immediately","C":"Email from your company's official domain","D":"A newsletter you subscribed to"},"answer":"B"},
    {"q":"What should you do if you receive an unexpected email asking for your password?","options":{"A":"Reply with your password immediately","B":"Click the link and enter your details","C":"Never share your password and report the email","D":"Forward it to all your contacts"},"answer":"C"},
    {"q":"Cybercriminals use phishing to steal which of the following?","options":{"A":"Login credentials and personal information","B":"Your physical mail","C":"Your office furniture","D":"Phone signals"},"answer":"A"},
    {"q":"How can you verify if an email link is safe before clicking?","options":{"A":"Just click it and see what happens","B":"Hover over the link to preview the actual URL","C":"Forward it to a friend to check","D":"Reply to the sender asking if it is safe"},"answer":"B"},
    {"q":"What does a phishing email often impersonate?","options":{"A":"Trusted organizations like banks, IT departments, or well-known companies","B":"Spam newsletters","C":"Antivirus software companies only","D":"Social media influencers"},"answer":"A"},
    {"q":"Which of the following email addresses looks suspicious?","options":{"A":"support@yourbank.com","B":"support@yourbank-secure-login.com","C":"hr@yourcompany.com","D":"noreply@amazon.com"},"answer":"B"},
    {"q":"What is Spear Phishing?","options":{"A":"A phishing attack targeted at a specific individual or organization","B":"A random phishing attack sent to millions of people","C":"A type of computer virus","D":"A secure login method"},"answer":"A"},
    {"q":"Which of the following is the BEST way to protect yourself from phishing attacks?","options":{"A":"Use the same password for all accounts","B":"Enable Two-Factor Authentication (2FA) and stay alert to suspicious emails","C":"Share your credentials only with trusted colleagues","D":"Click all links to verify if they are real"},"answer":"B"},
    {"q":"What should you do if you accidentally clicked a phishing link?","options":{"A":"Ignore it and continue working","B":"Immediately disconnect from the network, change your passwords, and report to IT","C":"Delete the email and forget about it","D":"Share the link with others to warn them"},"answer":"B"},
]


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def new_session_id():
    return secrets.token_urlsafe(16)


def create_schema(cur):
    cur.execute("""
    CREATE TABLE IF NOT EXISTS training_status (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT UNIQUE,
        rid TEXT,
        full_name TEXT,
        email TEXT,
        status TEXT DEFAULT 'Pending',
        current_step INTEGER DEFAULT 0,
        video1_completed INTEGER DEFAULT 0,
        video2_completed INTEGER DEFAULT 0,
        video3_completed INTEGER DEFAULT 0,
        video4_completed INTEGER DEFAULT 0,
        quiz_score INTEGER DEFAULT 0,
        quiz_status TEXT DEFAULT 'Not Attempted',
        video_started_at TEXT,
        completed_at TEXT,
        created_at TEXT,
        access_token TEXT,
        active_video TEXT
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS quiz_answers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL,
        rid TEXT,
        question_no INTEGER NOT NULL,
        selected_answer TEXT,
        answered_at TEXT,
        UNIQUE(session_id, question_no)
    )
    """)


def migrate_schema(cur):
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='training_status'")
    has_training_status = cur.fetchone() is not None
    if not has_training_status:
        create_schema(cur)
        return

    cur.execute("PRAGMA table_info(training_status)")
    columns = {row[1] for row in cur.fetchall()}
    cur.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='training_status'")
    table_sql = (cur.fetchone() or [""])[0] or ""
    normalized_sql = table_sql.upper().replace("\n", " ")
    needs_rebuild = "session_id" not in columns or "RID TEXT UNIQUE" in normalized_sql

    if needs_rebuild:
        cur.execute("ALTER TABLE training_status RENAME TO training_status_old")
        create_schema(cur)
        cur.execute("""
        INSERT INTO training_status (
            id, session_id, rid, full_name, email, status, current_step,
            video1_completed, video2_completed, video3_completed, video4_completed,
            quiz_score, quiz_status, video_started_at, completed_at, created_at, access_token, active_video
        )
        SELECT
            id,
            COALESCE(NULLIF(rid, ''), 'legacy-' || id),
            rid,
            full_name,
            email,
            COALESCE(status, 'Pending'),
            COALESCE(current_step, 0),
            COALESCE(video1_completed, 0),
            COALESCE(video2_completed, 0),
            COALESCE(video3_completed, 0),
            COALESCE(video4_completed, 0),
            COALESCE(quiz_score, 0),
            COALESCE(quiz_status, 'Not Attempted'),
            video_started_at,
            completed_at,
            COALESCE(video_started_at, completed_at, ?),
            lower(hex(randomblob(24))),
            NULL
        FROM training_status_old
        """, (now(),))
        cur.execute("DROP TABLE training_status_old")
    else:
        for col, definition in {
            "session_id": "TEXT",
            "rid": "TEXT",
            "current_step": "INTEGER DEFAULT 0",
            "video1_completed": "INTEGER DEFAULT 0",
            "video2_completed": "INTEGER DEFAULT 0",
            "video3_completed": "INTEGER DEFAULT 0",
            "video4_completed": "INTEGER DEFAULT 0",
            "quiz_score": "INTEGER DEFAULT 0",
            "quiz_status": "TEXT DEFAULT 'Not Attempted'",
            "created_at": "TEXT",
            "access_token": "TEXT",
            "active_video": "TEXT",
        }.items():
            if col not in columns:
                cur.execute(f"ALTER TABLE training_status ADD COLUMN {col} {definition}")

    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='quiz_answers'")
    has_quiz_answers = cur.fetchone() is not None
    if has_quiz_answers:
        cur.execute("PRAGMA table_info(quiz_answers)")
        answer_columns = {row[1] for row in cur.fetchall()}
        if "session_id" not in answer_columns:
            cur.execute("ALTER TABLE quiz_answers RENAME TO quiz_answers_old")
            cur.execute("""
            CREATE TABLE quiz_answers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                rid TEXT,
                question_no INTEGER NOT NULL,
                selected_answer TEXT,
                answered_at TEXT,
                UNIQUE(session_id, question_no)
            )
            """)
            cur.execute("""
            INSERT OR IGNORE INTO quiz_answers (id, session_id, rid, question_no, selected_answer, answered_at)
            SELECT id, rid, rid, question_no, selected_answer, answered_at FROM quiz_answers_old
            """)
            cur.execute("DROP TABLE quiz_answers_old")
    else:
        create_schema(cur)

    cur.execute("UPDATE training_status SET access_token=lower(hex(randomblob(24))) WHERE access_token IS NULL OR access_token=''")
    cur.execute("UPDATE training_status SET active_video=NULL WHERE active_video IS NULL")


def init_db():
    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    migrate_schema(cur)
    conn.commit()
    conn.close()


def get_user_from_gophish(rid):
    if not GOPHISH_DB_PATH:
        return None
    try:
        conn = sqlite3.connect(GOPHISH_DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT first_name, last_name, email FROM results WHERE r_id = ?", (rid,))
        row = cur.fetchone()
        conn.close()
        if row:
            full_name = f"{row[0] or ''} {row[1] or ''}".strip()
            return {"full_name": full_name or row[2] or "User", "email": row[2] or ""}
    except Exception:
        pass
    return None


def get_training_user(session_id):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
    SELECT session_id, rid, full_name, email, status, current_step,
           video1_completed, video2_completed, video3_completed, video4_completed,
           quiz_score, quiz_status, video_started_at, completed_at, access_token, active_video
    FROM training_status WHERE session_id=?
    """, (session_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "session_id": row[0], "rid": row[1] or "", "full_name": row[2] or "User", "email": row[3] or "",
        "status": row[4] or "Pending", "current_step": row[5] or 0,
        "video1_completed": row[6] or 0, "video2_completed": row[7] or 0,
        "video3_completed": row[8] or 0, "video4_completed": row[9] or 0,
        "quiz_score": row[10] or 0, "quiz_status": row[11] or "Not Attempted",
        "video_started_at": row[12], "completed_at": row[13],
        "access_token": row[14] or "", "active_video": row[15] or ""
    }


def session_cookie_name(session_id):
    safe_id = ''.join(ch for ch in session_id if ch.isalnum() or ch in ('-', '_'))
    return f"training_access_{safe_id}"


def set_session_cookie(response, session_id, access_token):
    response.set_cookie(
        session_cookie_name(session_id),
        access_token,
        max_age=60 * 60 * 8,
        httponly=True,
        samesite="Lax",
    )
    return response


def create_training_user(rid, full_name="User", email=""):
    session_id = new_session_id()
    access_token = secrets.token_urlsafe(32)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
    INSERT INTO training_status (session_id, rid, full_name, email, status, current_step, video_started_at, created_at, access_token)
    VALUES (?, ?, ?, ?, 'Pending', 0, ?, ?, ?)
    """, (session_id, rid, full_name, email, now(), now(), access_token))
    conn.commit()
    conn.close()
    return session_id, access_token


def authorize_session(session_id):
    user = get_training_user(session_id)
    if not user:
        return None
    cookie_token = request.cookies.get(session_cookie_name(session_id), "")
    if not cookie_token or not secrets.compare_digest(cookie_token, user["access_token"]):
        return None
    return user


def valid_video_index(video_id):
    if not video_id.startswith("video"):
        return None
    try:
        index = int(video_id.replace("video", "", 1))
    except ValueError:
        return None
    if index < 1 or index > VIDEO_COUNT:
        return None
    return index


def mark_video_started(session_id, video_id, current_step):
    index = valid_video_index(video_id)
    if index != min(current_step + 1, VIDEO_COUNT):
        return False
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
    UPDATE training_status
    SET video_started_at=COALESCE(video_started_at, ?), active_video=?
    WHERE session_id=?
    """, (now(), video_id, session_id))
    conn.commit()
    conn.close()
    return True


def update_video_complete(session_id, video_id):
    user = get_training_user(session_id)
    if not user:
        raise ValueError("Invalid training session")
    index = valid_video_index(video_id)
    expected_index = min(user["current_step"] + 1, VIDEO_COUNT)
    if index != expected_index or user["active_video"] != video_id:
        raise ValueError("Video is not available yet")
    col = f"video{index}_completed"
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(f"""
    UPDATE training_status
    SET {col}=1,
        current_step = CASE WHEN current_step < ? THEN ? ELSE current_step END,
        active_video=NULL
    WHERE session_id=?
    """, (index, index, session_id))
    conn.commit()
    conn.close()


def save_quiz_answer(session_id, rid, question_no, selected_answer):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
    INSERT INTO quiz_answers (session_id, rid, question_no, selected_answer, answered_at)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(session_id, question_no) DO UPDATE SET selected_answer=excluded.selected_answer, answered_at=excluded.answered_at
    """, (session_id, rid, question_no, selected_answer, now()))
    conn.commit()
    conn.close()


def get_answered_questions(session_id):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT question_no FROM quiz_answers WHERE session_id=?", (session_id,))
    answered = {row[0] for row in cur.fetchall()}
    conn.close()
    return answered


def next_quiz_question(session_id):
    answered = get_answered_questions(session_id)
    for question_no in range(1, len(QUIZ_QUESTIONS) + 1):
        if question_no not in answered:
            return question_no
    return len(QUIZ_QUESTIONS) + 1


def calculate_quiz_score(session_id):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT question_no, selected_answer FROM quiz_answers WHERE session_id=?", (session_id,))
    answers = dict(cur.fetchall())
    conn.close()
    return sum(1 for i, q in enumerate(QUIZ_QUESTIONS, start=1) if answers.get(i) == q["answer"])


def update_quiz_result(session_id, score, passed):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    if passed:
        cur.execute("""
        UPDATE training_status SET quiz_score=?, quiz_status='Passed', status='Completed', completed_at=? WHERE session_id=?
        """, (score, now(), session_id))
    else:
        cur.execute("""
        UPDATE training_status SET quiz_score=?, quiz_status='Failed', status='Pending' WHERE session_id=?
        """, (score, session_id))
    conn.commit()
    conn.close()


def reset_quiz(session_id):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM quiz_answers WHERE session_id=?", (session_id,))
    cur.execute("UPDATE training_status SET quiz_score=0, quiz_status='Not Attempted' WHERE session_id=?", (session_id,))
    conn.commit()
    conn.close()

BASE_CSS = """
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--primary:#003133;--primary2:#005356;--gold:#F5A94F;--bg:#eef3f4;--green:#28A745;--red:#EF1C25;--orange:#F59E0B}
body{font-family:'Segoe UI',Arial,sans-serif;background:radial-gradient(circle at 12% 18%,rgba(245,169,79,.18),transparent 25%),radial-gradient(circle at 86% 12%,rgba(0,83,86,.14),transparent 28%),var(--bg);color:var(--primary);min-height:100vh}
.header{height:82px;background:linear-gradient(135deg,var(--primary),var(--primary2));color:#fff;padding:0 32px;display:flex;align-items:center;justify-content:space-between;box-shadow:0 4px 20px rgba(0,0,0,.20)}
.brand{display:flex;align-items:center;gap:14px;font-weight:900;font-size:22px}.brand-mark{width:46px;height:46px;border-radius:12px;background:var(--gold);color:var(--primary);display:flex;align-items:center;justify-content:center;font-weight:900;font-size:24px}.header small{display:block;color:var(--gold);font-weight:850;margin-top:3px}
.intro-wrap{min-height:calc(100vh - 82px);display:flex;align-items:center;justify-content:center;padding:34px}.intro-card{width:min(1180px,96vw);background:rgba(255,255,255,.94);border-radius:24px;box-shadow:0 20px 60px rgba(0,0,0,.16);border-left:8px solid var(--gold);padding:44px}.intro-grid{display:grid;grid-template-columns:1fr .9fr;gap:34px;align-items:center}.warning-title{color:#8B0000;font-size:46px;line-height:1.12;margin-bottom:22px}.subtext{color:#4e6570;font-size:18px;line-height:1.8;margin-bottom:18px}.intro-art{min-height:390px;border-radius:24px;background:linear-gradient(rgba(0,49,51,.80),rgba(0,49,51,.80)),url('/static/training_awareness_bg.svg');background-size:cover;background-position:center;display:flex;align-items:center;justify-content:center;text-align:center;color:#fff;padding:30px}.intro-art h2{font-size:40px;margin-bottom:12px}
.btn{display:inline-flex;justify-content:center;align-items:center;padding:15px 24px;border:0;border-radius:12px;font-weight:900;text-decoration:none;cursor:pointer;font-size:16px}.btn-primary{background:var(--primary);color:#fff}.btn-primary:hover{background:var(--primary2)}.btn-danger{background:var(--red);color:#fff}
.lms-shell{min-height:calc(100vh - 82px);display:grid;grid-template-columns:280px 1fr;gap:22px;padding:22px}.video-menu{background:linear-gradient(180deg,var(--primary),#004446);border-radius:20px;padding:20px;display:flex;flex-direction:column;gap:12px;min-height:calc(100vh - 126px);box-shadow:0 10px 28px rgba(0,0,0,.14)}.video-menu-title{color:var(--gold);font-weight:900;margin-bottom:8px;font-size:14px;text-transform:uppercase;letter-spacing:.6px}.video-link{display:flex;justify-content:space-between;align-items:center;padding:15px 16px;border-radius:12px;text-decoration:none;color:#fff;background:rgba(255,255,255,.08);font-weight:850;border-left:4px solid transparent;transition:.22s}.video-link:hover{background:rgba(255,255,255,.15);transform:translateX(2px)}.video-link.active{background:var(--gold);color:var(--primary);border-left-color:#fff}.video-link.locked{background:rgba(255,255,255,.04);color:rgba(255,255,255,.46);pointer-events:none}.progress-card{margin-top:auto;background:rgba(255,255,255,.08);border-radius:14px;padding:15px;color:#fff}.progress-card p{font-size:12px;color:rgba(255,255,255,.72);font-weight:800;text-transform:uppercase}.progress-bar{height:10px;background:rgba(255,255,255,.16);border-radius:20px;margin-top:10px;overflow:hidden}.progress-fill{height:100%;background:var(--gold);border-radius:20px}
.video-stage{background:rgba(255,255,255,.94);border-radius:22px;box-shadow:0 12px 35px rgba(0,0,0,.10);padding:22px;min-height:calc(100vh - 126px);display:flex;flex-direction:column}.stage-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px}.stage-head h2{font-size:24px;color:var(--primary)}.stage-pill{background:#fff4df;color:#8a5a00;font-weight:900;padding:9px 13px;border-radius:999px;font-size:13px}.video-background{flex:1;min-height:560px;background:linear-gradient(135deg,rgba(0,49,51,.92),rgba(0,83,86,.78)),url('/static/training_awareness_bg.svg');background-size:cover;background-position:center;border-radius:20px;padding:18px;display:flex;flex-direction:column;justify-content:center;box-shadow:inset 0 0 0 1px rgba(255,255,255,.12)}.video-frame{width:100%;max-width:1100px;margin:0 auto;background:#061b1c;border-radius:18px;padding:14px;box-shadow:0 20px 60px rgba(0,0,0,.35)}video{width:100%;aspect-ratio:16/9;border-radius:14px;display:block;background:#000;pointer-events:auto;object-fit:contain}.play-btn{margin:16px auto 0;width:min(520px,100%);padding:16px 18px;border:0;border-radius:14px;background:var(--gold);color:var(--primary);font-size:17px;font-weight:950;cursor:pointer}.status-box{margin-top:18px;padding:16px 18px;border-radius:12px;background:#fff8e8;color:#8a5a00;font-weight:900;border-left:5px solid var(--gold)}.status-box.done{background:#edfff1;color:#146b2d;border-left-color:var(--green)}
.quiz-wrap{min-height:calc(100vh - 82px);padding:34px;display:flex;align-items:center;justify-content:center}.quiz-card{width:min(980px,96vw);background:#fff;border-radius:24px;padding:42px;box-shadow:0 16px 46px rgba(0,0,0,.12);border-top:6px solid var(--gold)}.quiz-top{display:flex;justify-content:space-between;align-items:center;gap:20px;margin-bottom:22px}.quiz-pill{background:#fff4df;color:#8a5a00;font-weight:900;padding:10px 14px;border-radius:999px;white-space:nowrap}.quiz-question-title{font-size:27px;color:var(--primary);line-height:1.35;margin:22px 0}.option{display:block;background:#f8fbfb;border:1.5px solid #dce6e8;border-radius:14px;padding:16px 18px;margin:12px 0;font-size:16px;cursor:pointer}.option:hover{border-color:var(--gold);background:#fff8e8}.option input{margin-right:10px}.quiz-actions{display:flex;justify-content:space-between;align-items:center;margin-top:26px}.success-card{width:min(900px,96vw);text-align:center;background:#fff;border-radius:24px;padding:54px;box-shadow:0 16px 46px rgba(0,0,0,.12);border-top:7px solid var(--green)}.success-icon{font-size:74px;margin-bottom:15px}.success-title{font-size:38px;color:var(--green);margin-bottom:14px}.fail-title{font-size:34px;color:var(--red);margin-bottom:14px}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:18px;margin:34px}.stat{background:#fff;padding:24px;border-radius:14px;box-shadow:0 3px 18px rgba(0,0,0,.08);border-top:5px solid var(--gold)}.stat h1{font-size:38px;color:var(--primary)}.stat p{font-weight:800;color:#65727a;text-transform:uppercase;font-size:12px;margin-top:8px}.stat.visitors{border-top-color:#1976D2}.stat.visitors h1{color:#1976D2}.stat.completed-box{border-top-color:var(--green)}.stat.completed-box h1{color:var(--green)}.stat.pending-box{border-top-color:var(--orange)}.stat.pending-box h1{color:var(--orange)}.table-wrap{margin:34px}table{width:100%;border-collapse:collapse;background:#fff;border-radius:14px;overflow:hidden;box-shadow:0 3px 18px rgba(0,0,0,.08)}th{background:var(--primary);color:#fff;text-align:left;padding:14px;font-size:13px}td{padding:13px 14px;border-bottom:1px solid #e8edf0;font-size:14px}.badge{padding:6px 10px;border-radius:6px;color:#fff;font-weight:800;font-size:12px}.completed{background:var(--green)}.pending{background:var(--orange)}.failed{background:var(--red)}@media(max-width:1150px){.lms-shell{grid-template-columns:1fr}.video-menu,.video-stage{min-height:auto}.intro-grid{grid-template-columns:1fr}.grid{grid-template-columns:1fr}}
</style>
"""

@app.route("/")
def home():
    rid = request.args.get("rid", "").strip()
    if not rid or not get_user_from_gophish(rid):
        abort(403)
    return redirect(url_for("intro", rid=rid))

@app.route("/intro")
def intro():
    rid = request.args.get("rid", "").strip()
    user = get_user_from_gophish(rid)
    if not rid or not user:
        abort(403)
    session_id, access_token = create_training_user(rid, user["full_name"], user["email"])
    html = """<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Adamsbridge Awareness Introduction</title>""" + BASE_CSS + """</head><body><div class='header'><div class='brand'><div class='brand-mark'>A</div><div>Adamsbridge<br><small>Phishing Awareness Training</small></div></div></div><div class='intro-wrap'><div class='intro-card'><div class='intro-grid'><div><h1 class='warning-title'>You clicked a simulated phishing link</h1><p class='subtext'>Hello <b>{{full_name}}</b>, this is an authorized security awareness exercise. You will now complete a phishing awareness training program.</p><p class='subtext'>Complete all {{video_count}} videos in order. After the final video, the quiz will open. Your dashboard status becomes <b>Completed</b> only after passing the quiz.</p><a class='btn btn-primary' href='/training?rid={{rid}}&sid={{session_id}}&video=video1'>Start Training</a></div><div class='intro-art'><div><h2>Security Awareness</h2><p>Watch videos - Answer quiz - Complete training</p></div></div></div></div></div></body></html>"""
    response = make_response(render_template_string(html, rid=rid, session_id=session_id, full_name=user["full_name"], video_count=VIDEO_COUNT))
    return set_session_cookie(response, session_id, access_token)

@app.route("/training")
def training_route():
    rid = request.args.get("rid", "").strip()
    if not rid:
        abort(403)
    session_id = request.args.get("sid", "").strip()
    video_id = request.args.get("video", "video1")
    if not session_id:
        user = get_user_from_gophish(rid)
        if not user:
            abort(403)
        session_id, access_token = create_training_user(rid, user["full_name"], user["email"])
        response = make_response(redirect(url_for("training_route", rid=rid, sid=session_id, video="video1")))
        return set_session_cookie(response, session_id, access_token)
    return training(rid, session_id, video_id)

def training(rid, session_id, video_id):
    user_data = authorize_session(session_id)
    if not user_data:
        return redirect(url_for("intro", rid=rid))
    if rid != user_data["rid"]:
        return redirect(url_for("training_route", rid=user_data["rid"], sid=session_id, video=video_id))

    requested_index = valid_video_index(video_id)
    current_step = user_data["current_step"]
    allowed_index = min(current_step + 1, VIDEO_COUNT)
    if not requested_index:
        return redirect(url_for("training_route", rid=rid, sid=session_id, video=f"video{allowed_index}"))
    if requested_index > allowed_index:
        return redirect(url_for("training_route", rid=rid, sid=session_id, video=f"video{allowed_index}"))

    selected_video = VIDEOS[requested_index - 1]
    if requested_index == allowed_index:
        mark_video_started(session_id, selected_video["id"], current_step)
    all_videos_completed = all(user_data[f"video{i}_completed"] for i in range(1, VIDEO_COUNT + 1))
    progress = int((current_step / VIDEO_COUNT) * 100)
    html = """<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Adamsbridge Training</title>""" + BASE_CSS + """</head><body><div class='header'><div class='brand'><div class='brand-mark'>A</div><div>Adamsbridge<br><small>Phishing Awareness Training</small></div></div></div><div class='lms-shell'><div class='video-menu'><div class='video-menu-title'>Training Videos</div>{% for v in videos %}{% set idx = loop.index %}{% set unlocked = idx <= current_step + 1 %}<a class='video-link {% if v.id == selected_video.id %}active{% endif %} {% if not unlocked %}locked{% endif %}' href='{% if unlocked %}/training?rid={{rid}}&sid={{session_id}}&video={{v.id}}{% else %}javascript:void(0){% endif %}'><span>{{v.title}}</span><span>{% if idx <= current_step %}Done{% elif unlocked %}Play{% else %}Locked{% endif %}</span></a>{% endfor %}<a class='video-link {% if not all_videos_completed %}locked{% endif %}' href='{% if all_videos_completed %}/quiz?rid={{rid}}&sid={{session_id}}&q=1{% else %}javascript:void(0){% endif %}'><span>Final Quiz</span><span>{% if all_videos_completed %}Open{% else %}Locked{% endif %}</span></a><div class='progress-card'><p>Training Progress</p><div style='font-size:24px;font-weight:900;margin-top:6px'>{{progress}}%</div><div class='progress-bar'><div class='progress-fill' style='width:{{progress}}%'></div></div></div></div><div class='video-stage'><div class='stage-head'><h2>{{selected_video.title}}</h2><div class='stage-pill'>No skip - Normal speed - Locked sequence</div></div><div class='video-background'><div class='video-frame'><video id='trainingVideo' preload='auto' playsinline webkit-playsinline controlsList='nodownload noplaybackrate' disablePictureInPicture><source src='/static/{{selected_video.filename}}' type='video/mp4'>Your browser does not support video playback.</video></div><button id='playBtn' class='play-btn'>Start {{selected_video.title}}</button><div id='status' class='status-box'>Training status: Please watch {{selected_video.title}} fully.</div></div></div></div><script>const rid='{{rid}}';const sessionId='{{session_id}}';const selectedVideo='{{selected_video.id}}';const video=document.getElementById('trainingVideo');const playBtn=document.getElementById('playBtn');const statusBox=document.getElementById('status');let maxTime=0;let completedSent=false;video.controls=false;video.defaultPlaybackRate=1;video.playbackRate=1;video.load();function setStatus(message){statusBox.innerText=message;}playBtn.addEventListener('click',function(){setStatus('Loading video...');const playPromise=video.play();if(playPromise&&playPromise.then){playPromise.then(()=>{playBtn.style.display='none';setStatus('Training status: Video is playing. Please watch it fully.');}).catch(()=>{playBtn.style.display='block';setStatus('Video could not start. Please tap Start again or refresh the page.');});}else{playBtn.style.display='none';setStatus('Training status: Video is playing. Please watch it fully.');}});video.addEventListener('timeupdate',function(){if(!video.seeking){maxTime=Math.max(maxTime,video.currentTime);}});video.addEventListener('seeking',function(){if(video.currentTime>maxTime+1){video.currentTime=maxTime;}});video.addEventListener('ratechange',function(){if(video.playbackRate!==1){video.playbackRate=1;}});video.addEventListener('waiting',function(){setStatus('Training status: Video is buffering.');});video.addEventListener('playing',function(){setStatus('Training status: Video is playing. Please watch it fully.');});video.addEventListener('error',function(){playBtn.style.display='block';setStatus('Video failed to load. Please refresh the page or contact support.');});video.addEventListener('contextmenu',function(e){e.preventDefault();});video.addEventListener('ended',function(){if(completedSent)return;completedSent=true;setStatus('Saving video completion...');fetch('/complete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({rid:rid,sid:sessionId,video:selectedVideo})}).then(r=>r.json()).then(data=>{if(!data.success){completedSent=false;setStatus(data.message||'Please continue from the highlighted training step.');return;}statusBox.classList.add('done');setStatus(data.message);setTimeout(function(){if(data.next_url){window.location=data.next_url;}else{window.location.reload();}},900);}).catch(()=>{completedSent=false;setStatus('Completion could not be saved. Please check your connection and replay the last few seconds.');});});</script></body></html>"""
    return render_template_string(html, rid=rid, session_id=session_id, full_name=user_data["full_name"], videos=VIDEOS, selected_video=selected_video, current_step=current_step, all_videos_completed=all_videos_completed, progress=progress)

@app.route("/start", methods=["POST"])
def start_training():
    data = request.get_json(silent=True) or {}
    session_id = data.get("sid", "")
    video_id = data.get("video", "video1")
    user = authorize_session(session_id)
    if not user:
        return jsonify({"success": False, "message": "This training session is no longer valid."}), 403
    if not mark_video_started(session_id, video_id, user["current_step"]):
        return jsonify({"success": False, "message": "Please continue from the highlighted training step."}), 403
    return jsonify({"success": True})

@app.route("/complete", methods=["POST"])
def complete_training():
    data = request.get_json(silent=True) or {}
    session_id = data.get("sid", "")
    video_id = data.get("video", "video1")
    user = authorize_session(session_id)
    if not user:
        return jsonify({"success": False, "message": "This training session is no longer valid."}), 403
    rid = user["rid"]
    try:
        update_video_complete(session_id, video_id)
    except ValueError:
        return jsonify({"success": False, "message": "Please watch the current video before continuing."}), 403
    index = valid_video_index(video_id) or 1
    if index < VIDEO_COUNT:
        return jsonify({"success": True, "next_url": f"/training?rid={rid}&sid={session_id}&video=video{index + 1}", "message": f"Video {index} completed. Next video unlocked."})
    return jsonify({"success": True, "next_url": f"/quiz?rid={rid}&sid={session_id}&q=1", "message": "All videos completed. Final quiz unlocked."})

@app.route("/quiz", methods=["GET", "POST"])
def quiz():
    rid = request.args.get("rid", "")
    session_id = request.args.get("sid", "")
    try:
        q_no = int(request.args.get("q", "1"))
    except ValueError:
        q_no = 1
    user = authorize_session(session_id)
    if not user:
        return redirect(url_for("intro", rid=rid))
    if rid != user["rid"]:
        return redirect(url_for("quiz", rid=user["rid"], sid=session_id, q=1))
    all_videos_completed = all(user[f"video{i}_completed"] for i in range(1, VIDEO_COUNT + 1))
    if not all_videos_completed:
        allowed_index = min(user["current_step"] + 1, VIDEO_COUNT)
        return redirect(url_for("training_route", rid=user["rid"], sid=session_id, video=f"video{allowed_index}"))

    next_question = next_quiz_question(session_id)
    if next_question > len(QUIZ_QUESTIONS):
        return redirect(url_for("quiz_result", rid=user["rid"], sid=session_id))
    if q_no != next_question:
        return redirect(url_for("quiz", rid=user["rid"], sid=session_id, q=next_question))

    if request.method == "POST":
        selected = request.form.get("answer", "")
        if not selected:
            return redirect(url_for("quiz", rid=user["rid"], sid=session_id, q=q_no))
        save_quiz_answer(session_id, user["rid"], q_no, selected)
        next_question = next_quiz_question(session_id)
        if next_question <= len(QUIZ_QUESTIONS):
            return redirect(url_for("quiz", rid=user["rid"], sid=session_id, q=next_question))
        return redirect(url_for("quiz_result", rid=user["rid"], sid=session_id))

    question = QUIZ_QUESTIONS[q_no - 1]
    progress = int((q_no / len(QUIZ_QUESTIONS)) * 100)
    html = """<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Final Quiz</title>""" + BASE_CSS + """</head><body><div class='header'><div class='brand'><div class='brand-mark'>A</div><div>Adamsbridge<br><small>Final Awareness Quiz</small></div></div></div><div class='quiz-wrap'><div class='quiz-card'><div class='quiz-top'><div><h1 class='warning-title' style='font-size:34px;margin-bottom:8px'>Final Quiz</h1><p class='subtext' style='margin-bottom:0'>Question {{q_no}} of {{total_questions}}</p></div><div class='quiz-pill'>Pass Mark: {{pass_score}} / {{total_questions}}</div></div><div class='progress-bar' style='margin-bottom:22px'><div class='progress-fill' style='width:{{progress}}%'></div></div><form method='POST'><h2 class='quiz-question-title'>{{question.q}}</h2>{% for key, value in question.options.items() %}<label class='option'><input type='radio' name='answer' value='{{key}}' required><b>{{key}})</b> {{value}}</label>{% endfor %}<div class='quiz-actions'><div class='subtext' style='margin:0;font-size:14px'>Answer this question to continue.</div><button type='submit' class='btn btn-primary'>{% if q_no == total_questions %}Submit Quiz{% else %}Next Question{% endif %}</button></div></form></div></div></body></html>"""
    return render_template_string(html, rid=user["rid"], session_id=session_id, q_no=q_no, question=question, total_questions=len(QUIZ_QUESTIONS), pass_score=PASS_SCORE, progress=progress)

@app.route("/quiz-result")
def quiz_result():
    rid = request.args.get("rid", "")
    session_id = request.args.get("sid", "")
    user = authorize_session(session_id)
    if not user:
        return redirect(url_for("intro", rid=rid))
    all_videos_completed = all(user[f"video{i}_completed"] for i in range(1, VIDEO_COUNT + 1))
    if not all_videos_completed:
        allowed_index = min(user["current_step"] + 1, VIDEO_COUNT)
        return redirect(url_for("training_route", rid=user["rid"], sid=session_id, video=f"video{allowed_index}"))
    if next_quiz_question(session_id) <= len(QUIZ_QUESTIONS):
        return redirect(url_for("quiz", rid=user["rid"], sid=session_id, q=next_quiz_question(session_id)))
    score = calculate_quiz_score(session_id)
    passed = score >= PASS_SCORE
    update_quiz_result(session_id, score, passed)
    if passed:
        return redirect(url_for("success", rid=user["rid"], sid=session_id, score=score))
    html = """<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Quiz Result</title>""" + BASE_CSS + """</head><body><div class='header'><div class='brand'><div class='brand-mark'>A</div><div>Adamsbridge<br><small>Final Awareness Quiz</small></div></div></div><div class='quiz-wrap'><div class='success-card' style='border-top-color:var(--red)'><div class='success-icon'>X</div><h1 class='fail-title'>Quiz Not Passed</h1><p class='subtext'>Your score is <b>{{score}} / {{total}}</b>. You need at least <b>{{pass_score}} / {{total}}</b>.</p><p class='subtext'>Please review the training and try the quiz again.</p><a class='btn btn-danger' href='/reset-quiz?rid={{rid}}&sid={{session_id}}'>Retry Quiz</a></div></div></body></html>"""
    return render_template_string(html, rid=user["rid"], session_id=session_id, score=score, total=len(QUIZ_QUESTIONS), pass_score=PASS_SCORE)

@app.route("/success")
def success():
    rid = request.args.get("rid", "")
    session_id = request.args.get("sid", "")
    score = request.args.get("score", "")
    user = authorize_session(session_id)
    if not user:
        return redirect(url_for("intro", rid=rid))
    if user["status"] != "Completed" or user["quiz_status"] != "Passed":
        return redirect(url_for("quiz", rid=user["rid"], sid=session_id, q=1))
    html = """<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Training Completed</title>""" + BASE_CSS + """</head><body><div class='header'><div class='brand'><div class='brand-mark'>A</div><div>Adamsbridge<br><small>Phishing Awareness Training</small></div></div></div><div class='quiz-wrap'><div class='success-card'><div class='success-icon'>OK</div><h1 class='success-title'>You have successfully completed the training</h1><p class='subtext'>Congratulations <b>{{full_name}}</b>. You passed the final quiz with a score of <b>{{score}} / {{total}}</b>.</p><p class='subtext'>Your phishing awareness training completion has been recorded in the dashboard.</p></div></div></body></html>"""
    return render_template_string(html, full_name=user["full_name"], score=score or user["quiz_score"], total=len(QUIZ_QUESTIONS))

@app.route("/reset-quiz")
def reset_quiz_route():
    rid = request.args.get("rid", "")
    session_id = request.args.get("sid", "")
    user = authorize_session(session_id)
    if not user:
        return redirect(url_for("intro", rid=rid))
    reset_quiz(session_id)
    return redirect(url_for("quiz", rid=user["rid"], sid=session_id, q=1))

@app.route("/training-users")
def training_users():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
    SELECT full_name, email, status, video1_completed, video2_completed, video3_completed, video4_completed,
           quiz_score, quiz_status, video_started_at, completed_at
    FROM training_status
    ORDER BY CASE status WHEN 'Completed' THEN 1 ELSE 2 END, completed_at DESC, video_started_at DESC
    """)
    rows = cur.fetchall()
    visitors = len(rows)
    completed = sum(1 for r in rows if r[2] == "Completed")
    pending = visitors - completed
    conn.close()
    html = """<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Training Users - Adamsbridge</title>""" + BASE_CSS + """</head><body><div class='header'><div class='brand'><div class='brand-mark'>A</div><div>Adamsbridge<br><small>Training Users Dashboard</small></div></div></div><div class='grid'><div class='stat visitors'><h1>{{visitors}}</h1><p>Training Visitors</p></div><div class='stat completed-box'><h1>{{completed}}</h1><p>Training Completed</p></div><div class='stat pending-box'><h1>{{pending}}</h1><p>Training Pending</p></div></div><div class='table-wrap'><table><thead><tr><th>Name</th><th>Email</th><th>Status</th><th>V1</th><th>V2</th><th>V3</th><th>V4</th><th>Quiz</th><th>Score</th><th>Completed At</th></tr></thead><tbody>{% if rows %}{% for r in rows %}<tr><td><b>{{r[0]}}</b></td><td>{{r[1] or 'N/A'}}</td><td>{% if r[2] == 'Completed' %}<span class='badge completed'>Completed</span>{% else %}<span class='badge pending'>Pending</span>{% endif %}</td><td>{% if r[3] %}Done{% else %}Locked{% endif %}</td><td>{% if r[4] %}Done{% else %}Locked{% endif %}</td><td>{% if r[5] %}Done{% else %}Locked{% endif %}</td><td>{% if r[6] %}Done{% else %}Locked{% endif %}</td><td>{% if r[8] == 'Passed' %}<span class='badge completed'>Passed</span>{% elif r[8] == 'Failed' %}<span class='badge failed'>Failed</span>{% else %}<span class='badge pending'>Not Attempted</span>{% endif %}</td><td>{{r[7]}} / {{total_questions}}</td><td>{{r[10] or 'N/A'}}</td></tr>{% endfor %}{% else %}<tr><td colspan='10' style='text-align:center;padding:35px;color:#777'>No training records yet</td></tr>{% endif %}</tbody></table></div></body></html>"""
    return render_template_string(html, rows=rows, visitors=visitors, pending=pending, completed=completed, total_questions=len(QUIZ_QUESTIONS))

@app.route("/health")
def health():
    return jsonify({"status": "ok"})


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=False)
