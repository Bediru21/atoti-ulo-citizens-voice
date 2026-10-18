import os, sqlite3, secrets, csv, io
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response, abort
from werkzeug.security import generate_password_hash, check_password_hash

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DATABASE_PATH", os.path.join(APP_DIR, "citizens_voice.db"))
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

STATUSES = [
    ("new", "አዲስ ተመዝግቧል"),
    ("assigned", "ለሚመለከተው ክፍል ተልኳል"),
    ("in_progress", "በሂደት ላይ"),
    ("responded", "ምላሽ ተሰጥቷል"),
    ("resolved", "ተፈትቷል/ተዘግቷል"),
]
CATEGORIES = [
    "የመሬት አስተዳደር", "የውሃ አቅርቦት", "የጤና አገልግሎት",
    "የትምህርት አገልግሎት", "መንገድና መሠረተ ልማት",
    "የንግድና ፈቃድ አገልግሎት", "የአስተዳደር መዘግየት",
    "አድልዎ/የእኩልነት ጉዳይ", "ግልጽነትና ተጠያቂነት", "ሌሎች"
]
INSTITUTIONS = [
    "የወረዳ አስተዳደር", "የፍትሕ ጽሕፈት ቤት", "የመሬት አስተዳደር",
    "የጤና ጽሕፈት ቤት", "የትምህርት ጽሕፈት ቤት",
    "የውሃና ኢነርጂ ክፍል", "የመንገድና መሠረተ ልማት", "ሌላ/አላውቅም"
]
KEBELES = [f"ቀበሌ {i}" for i in range(1, 21)] + ["ሌላ"]

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS complaints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tracking_id TEXT UNIQUE NOT NULL,
            submitted_at TEXT NOT NULL,
            full_name TEXT,
            phone TEXT,
            kebele TEXT NOT NULL,
            institution TEXT NOT NULL,
            category TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            incident_date TEXT,
            location TEXT,
            status TEXT NOT NULL DEFAULT 'new',
            assigned_to TEXT,
            admin_response TEXT,
            updated_at TEXT NOT NULL
        )""")
        con.execute("""CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )""")
        # Create a first admin only when credentials are explicitly configured.
        username = os.environ.get("ADMIN_USERNAME")
        password = os.environ.get("ADMIN_PASSWORD")
        if username and password:
            exists = con.execute("SELECT id FROM admins WHERE username=?", (username,)).fetchone()
            if not exists:
                con.execute("INSERT INTO admins(username,password_hash) VALUES(?,?)",
                            (username, generate_password_hash(password)))

init_db()

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin_id"):
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapper

def status_label(code):
    return dict(STATUSES).get(code, code)

@app.context_processor
def inject_globals():
    return {"statuses": STATUSES, "status_label": status_label, "categories": CATEGORIES,
            "institutions": INSTITUTIONS, "kebeles": KEBELES}

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/submit", methods=["GET", "POST"])
def submit():
    if request.method == "POST":
        fields = {k: (request.form.get(k) or "").strip() for k in [
            "full_name", "phone", "kebele", "institution", "category", "title",
            "description", "incident_date", "location"
        ]}
        required = ["kebele", "institution", "category", "title", "description"]
        if any(not fields[x] for x in required):
            flash("እባክዎ በ* የተመለከቱትን አስፈላጊ መረጃዎች ይሙሉ።", "error")
            return render_template("submit.html", values=fields)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        year = datetime.now().year
        with db() as con:
            cur = con.execute("""INSERT INTO complaints
                (tracking_id, submitted_at, full_name, phone, kebele, institution, category,
                 title, description, incident_date, location, status, updated_at)
                 VALUES ('PENDING',?,?,?,?,?,?,?,?,?,?, 'new',?)""",
                (now, fields["full_name"], fields["phone"], fields["kebele"], fields["institution"],
                 fields["category"], fields["title"], fields["description"], fields["incident_date"],
                 fields["location"], now))
            tracking = f"AU-{year}-{cur.lastrowid:06d}"
            con.execute("UPDATE complaints SET tracking_id=? WHERE id=?", (tracking, cur.lastrowid))
        return render_template("submitted.html", tracking=tracking)
    return render_template("submit.html", values={})

@app.route("/track", methods=["GET", "POST"])
def track():
    complaint = None
    if request.method == "POST":
        tracking = (request.form.get("tracking_id") or "").strip().upper()
        with db() as con:
            complaint = con.execute("SELECT tracking_id,submitted_at,kebele,institution,category,title,status,updated_at,admin_response FROM complaints WHERE tracking_id=?",
                                    (tracking,)).fetchone()
        if not complaint:
            flash("ይህ የመከታተያ ቁጥር አልተገኘም። ቁጥሩን ያረጋግጡ።", "error")
    return render_template("track.html", complaint=complaint)

@app.route("/admin/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        with db() as con:
            admin = con.execute("SELECT * FROM admins WHERE username=?", (username,)).fetchone()
        if admin and check_password_hash(admin["password_hash"], password):
            session.clear()
            session["admin_id"] = admin["id"]
            session["admin_username"] = admin["username"]
            return redirect(request.args.get("next") or url_for("dashboard"))
        flash("የተጠቃሚ ስም ወይም የይለፍ ቃል ትክክል አይደለም።", "error")
    return render_template("login.html")

@app.route("/admin/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

@app.route("/admin")
@admin_required
def dashboard():
    status_filter = request.args.get("status", "")
    query = "SELECT * FROM complaints"
    params = []
    if status_filter in dict(STATUSES):
        query += " WHERE status=?"
        params.append(status_filter)
    query += " ORDER BY submitted_at DESC"
    with db() as con:
        rows = con.execute(query, params).fetchall()
        counts = {code: con.execute("SELECT COUNT(*) FROM complaints WHERE status=?", (code,)).fetchone()[0]
                  for code, _ in STATUSES}
        total = con.execute("SELECT COUNT(*) FROM complaints").fetchone()[0]
    return render_template("dashboard.html", rows=rows, counts=counts, total=total, status_filter=status_filter)

@app.route("/admin/case/<tracking_id>", methods=["GET", "POST"])
@admin_required
def case_detail(tracking_id):
    with db() as con:
        case = con.execute("SELECT * FROM complaints WHERE tracking_id=?", (tracking_id,)).fetchone()
        if not case:
            abort(404)
        if request.method == "POST":
            status = request.form.get("status", "new")
            if status not in dict(STATUSES):
                status = "new"
            assigned_to = (request.form.get("assigned_to") or "").strip()
            response = (request.form.get("admin_response") or "").strip()
            updated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            con.execute("UPDATE complaints SET status=?, assigned_to=?, admin_response=?, updated_at=? WHERE tracking_id=?",
                        (status, assigned_to, response, updated, tracking_id))
            flash("የጉዳዩ መረጃ ተዘምኗል።", "success")
            return redirect(url_for("case_detail", tracking_id=tracking_id))
    with db() as con:
        case = con.execute("SELECT * FROM complaints WHERE tracking_id=?", (tracking_id,)).fetchone()
    return render_template("case_detail.html", case=case)

@app.route("/admin/reports")
@admin_required
def reports():
    with db() as con:
        by_category = con.execute("SELECT category, COUNT(*) AS n FROM complaints GROUP BY category ORDER BY n DESC").fetchall()
        by_institution = con.execute("SELECT institution, COUNT(*) AS n FROM complaints GROUP BY institution ORDER BY n DESC").fetchall()
        by_kebele = con.execute("SELECT kebele, COUNT(*) AS n FROM complaints GROUP BY kebele ORDER BY n DESC").fetchall()
        by_status = con.execute("SELECT status, COUNT(*) AS n FROM complaints GROUP BY status").fetchall()
        monthly = con.execute("SELECT substr(submitted_at,1,7) AS month, COUNT(*) AS n FROM complaints GROUP BY month ORDER BY month DESC LIMIT 12").fetchall()
    return render_template("reports.html", by_category=by_category, by_institution=by_institution,
                           by_kebele=by_kebele, by_status=by_status, monthly=monthly)

@app.route("/admin/export.csv")
@admin_required
def export_csv():
    with db() as con:
        rows = con.execute("SELECT tracking_id,submitted_at,full_name,phone,kebele,institution,category,title,description,incident_date,location,status,assigned_to,admin_response,updated_at FROM complaints ORDER BY submitted_at DESC").fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Tracking ID","Submitted at","Full name","Phone","Kebele","Institution","Category","Title","Description","Incident date","Location","Status","Assigned to","Admin response","Updated at"])
    for row in rows:
        writer.writerow(list(row))
    response = make_response("\\ufeff" + output.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = "attachment; filename=atoti_ulo_complaints.csv"
    return response

@app.errorhandler(404)
def not_found(_):
    return render_template("404.html"), 404

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
