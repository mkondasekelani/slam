"""SLAMS - School Library & Asset Management System (Flask + SQLite)."""
import csv, io, os, secrets, sqlite3
from datetime import date, datetime
from functools import wraps

from flask import (Flask, Response, abort, flash, g, jsonify, redirect,
                   render_template, request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("SLAMS_DB", os.path.join(BASE, "slams.db"))
KEY_PATH = os.path.join(BASE, ".secret_key")

app = Flask(__name__)
if not os.path.exists(KEY_PATH):
    with open(KEY_PATH, "w") as f:
        f.write(secrets.token_hex(32))
app.secret_key = open(KEY_PATH).read().strip()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

CONDITIONS = ["Good", "Fair", "Poor"]
ROLES = ["admin", "librarian", "technician"]

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, full_name TEXT NOT NULL,
  password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'librarian', active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS categories(
  id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, prefix TEXT UNIQUE NOT NULL,
  bulk INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS locations(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL);
CREATE TABLE IF NOT EXISTS assets(
  id INTEGER PRIMARY KEY, asset_code TEXT UNIQUE, name TEXT NOT NULL,
  category_id INTEGER NOT NULL REFERENCES categories(id),
  location_id INTEGER REFERENCES locations(id),
  serial_number TEXT, isbn TEXT, author_brand TEXT,
  quantity INTEGER NOT NULL DEFAULT 1 CHECK(quantity >= 0),
  damaged_qty INTEGER NOT NULL DEFAULT 0 CHECK(damaged_qty >= 0),
  condition TEXT NOT NULL DEFAULT 'Good', notes TEXT,
  active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS students(
  id INTEGER PRIMARY KEY, admission_no TEXT UNIQUE NOT NULL, name TEXT NOT NULL, class_name TEXT);
CREATE TABLE IF NOT EXISTS staff(
  id INTEGER PRIMARY KEY, staff_no TEXT UNIQUE NOT NULL, name TEXT NOT NULL, department TEXT);
CREATE TABLE IF NOT EXISTS assignments(
  id INTEGER PRIMARY KEY, asset_id INTEGER NOT NULL REFERENCES assets(id),
  recipient_type TEXT NOT NULL CHECK(recipient_type IN ('student','staff')),
  recipient_id INTEGER NOT NULL, qty INTEGER NOT NULL DEFAULT 1 CHECK(qty > 0),
  issue_date TEXT NOT NULL, due_date TEXT, status TEXT NOT NULL DEFAULT 'Issued',
  issued_by INTEGER REFERENCES users(id), notes TEXT);
CREATE TABLE IF NOT EXISTS returns(
  id INTEGER PRIMARY KEY, assignment_id INTEGER NOT NULL REFERENCES assignments(id),
  return_date TEXT NOT NULL, damaged_qty INTEGER NOT NULL DEFAULT 0,
  condition TEXT, notes TEXT, received_by INTEGER REFERENCES users(id));
CREATE TABLE IF NOT EXISTS maintenance(
  id INTEGER PRIMARY KEY, asset_id INTEGER NOT NULL REFERENCES assets(id),
  qty INTEGER NOT NULL DEFAULT 1, issue TEXT NOT NULL, reported_date TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Open', resolved_date TEXT, cost REAL, notes TEXT,
  reported_by INTEGER REFERENCES users(id));
CREATE TABLE IF NOT EXISTS activity_logs(
  id INTEGER PRIMARY KEY, ts TEXT NOT NULL, user_id INTEGER, username TEXT,
  action TEXT NOT NULL, details TEXT);
CREATE INDEX IF NOT EXISTS ix_assign_open ON assignments(asset_id, status);
"""

# Inner query computes assigned units; outer computes available units.
ASSET_SQL = """
SELECT *, quantity - damaged_qty - assigned AS available FROM (
  SELECT a.*, c.name AS category, c.prefix AS prefix, c.bulk AS bulk, l.name AS location,
    COALESCE((SELECT SUM(x.qty) FROM assignments x
              WHERE x.asset_id = a.id AND x.status = 'Issued'), 0) AS assigned
  FROM assets a JOIN categories c ON c.id = a.category_id
  LEFT JOIN locations l ON l.id = a.location_id)
"""

RECIPIENT_SQL = """
CASE a.recipient_type
  WHEN 'student' THEN (SELECT name || ' (' || admission_no || ')' FROM students WHERE id = a.recipient_id)
  ELSE (SELECT name || ' (' || staff_no || ')' FROM staff WHERE id = a.recipient_id) END
"""


# ---------------------------------------------------------------- database
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()


def init_db():
    con = sqlite3.connect(DB_PATH)
    con.executescript(SCHEMA)
    if not con.execute("SELECT 1 FROM users").fetchone():
        con.execute("INSERT INTO users(username, full_name, password_hash, role) VALUES(?,?,?,?)",
                    ("admin", "System Administrator", generate_password_hash("admin123"), "admin"))
    if not con.execute("SELECT 1 FROM categories").fetchone():
        con.executemany("INSERT INTO categories(name, prefix, bulk) VALUES(?,?,?)", [
            ("Textbook", "TXT", 1), ("Reference Book", "REF", 1), ("Laboratory Equipment", "LAB", 0),
            ("Computer", "PC", 0), ("Computer Peripheral", "PER", 0), ("Printer", "PRN", 0),
            ("Networking Equipment", "NET", 0)])
    if not con.execute("SELECT 1 FROM locations").fetchone():
        con.executemany("INSERT INTO locations(name) VALUES(?)", [
            ("Library",), ("Science Laboratory",), ("Computer Lab 1",), ("Computer Lab 2",), ("Admin Office",)])
    con.commit()
    con.close()


def log(action, details=""):
    db().execute("INSERT INTO activity_logs(ts, user_id, username, action, details) VALUES(?,?,?,?,?)",
                 (datetime.now().isoformat(" ", "seconds"), session.get("uid"), session.get("username"),
                  action, details))


def get_asset(asset_id=None, code=None):
    if asset_id is not None:
        return db().execute(ASSET_SQL + " WHERE id = ?", (asset_id,)).fetchone()
    return db().execute(ASSET_SQL + " WHERE asset_code = ? COLLATE NOCASE", (code,)).fetchone()


def find_asset_by_scan(text):
    """Match a scanned/typed value against asset code, serial number or ISBN."""
    text = (text or "").strip()
    if not text:
        return None
    return db().execute(ASSET_SQL + """ WHERE active = 1 AND (asset_code = ? COLLATE NOCASE
        OR serial_number = ? COLLATE NOCASE OR isbn = ?) LIMIT 1""", (text, text, text)).fetchone()


# -------------------------------------------------------------------- auth
def login_required(f):
    @wraps(f)
    def wrap(*a, **k):
        if not session.get("uid"):
            return redirect(url_for("login", next=request.path))
        return f(*a, **k)
    return wrap


def admin_required(f):
    @wraps(f)
    @login_required
    def wrap(*a, **k):
        if session.get("role") != "admin":
            abort(403)
        return f(*a, **k)
    return wrap


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


@app.before_request
def csrf_protect():
    if request.method == "POST":
        sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
        if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
            abort(400, "Invalid or missing security token. Reload the page and try again.")


app.jinja_env.globals.update(csrf_token=csrf_token, today=lambda: date.today().isoformat(),
                             CONDITIONS=CONDITIONS)


@app.errorhandler(403)
def forbidden(_):
    return render_template("error.html", code=403, msg="You don't have permission to do that."), 403


@app.errorhandler(400)
def bad_request(e):
    return render_template("error.html", code=400, msg=getattr(e, "description", "Bad request")), 400


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = db().execute("SELECT * FROM users WHERE username = ? AND active = 1",
                         (request.form["username"].strip(),)).fetchone()
        if u and check_password_hash(u["password_hash"], request.form["password"]):
            session.clear()
            session.update(uid=u["id"], username=u["username"], role=u["role"], name=u["full_name"])
            log("login")
            db().commit()
            nxt = request.args.get("next", "")
            return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("dashboard"))
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


# --------------------------------------------------------------- dashboard
@app.route("/")
@login_required
def dashboard():
    d = db()
    row = d.execute("""SELECT COALESCE(SUM(quantity),0) total, COALESCE(SUM(assigned),0) assigned,
        COALESCE(SUM(damaged_qty),0) damaged, COALESCE(SUM(available),0) available
        FROM (""" + ASSET_SQL + ") WHERE active = 1").fetchone()
    overdue = d.execute("""SELECT COALESCE(SUM(qty),0) FROM assignments
        WHERE status='Issued' AND due_date IS NOT NULL AND due_date < ?""", (date.today().isoformat(),)).fetchone()[0]
    recent = d.execute("""SELECT 'Issued' kind, a.issue_date dt, s.name asset, s.asset_code, a.qty,
        """ + RECIPIENT_SQL + """ who FROM assignments a JOIN assets s ON s.id = a.asset_id
        UNION ALL SELECT 'Returned', r.return_date, s.name, s.asset_code, a.qty,
        """ + RECIPIENT_SQL + """ FROM returns r JOIN assignments a ON a.id = r.assignment_id
        JOIN assets s ON s.id = a.asset_id ORDER BY dt DESC LIMIT 10""").fetchall()
    by_cat = d.execute("""SELECT category, SUM(quantity) total, SUM(assigned) assigned,
        SUM(available) available FROM (""" + ASSET_SQL + """) WHERE active = 1
        GROUP BY category ORDER BY category""").fetchall()
    return render_template("dashboard.html", s=row, overdue=overdue, recent=recent, by_cat=by_cat)


# ------------------------------------------------------------------ assets
def lookups():
    d = db()
    return (d.execute("SELECT * FROM categories ORDER BY name").fetchall(),
            d.execute("SELECT * FROM locations ORDER BY name").fetchall())


@app.route("/assets")
@login_required
def assets():
    q = request.args.get("q", "").strip()
    cat = request.args.get("category", "")
    loc = request.args.get("location", "")
    show = request.args.get("show", "active")
    sql, args = ASSET_SQL + " WHERE 1=1", []
    if show != "all":
        sql += " AND active = 1"
    if q:
        sql += """ AND (name LIKE ? OR asset_code LIKE ? OR serial_number LIKE ?
                   OR isbn LIKE ? OR author_brand LIKE ?)"""
        args += [f"%{q}%"] * 5
    if cat:
        sql += " AND category_id = ?"
        args.append(cat)
    if loc:
        sql += " AND location_id = ?"
        args.append(loc)
    rows = db().execute(sql + " ORDER BY name LIMIT 500", args).fetchall()
    # A scanner "types" the code then presses Enter: jump straight to an exact match.
    if q and request.args.get("go") and len(rows) >= 1:
        exact = find_asset_by_scan(q)
        if exact:
            return redirect(url_for("asset_detail", asset_id=exact["id"]))
    cats, locs = lookups()
    return render_template("assets.html", rows=rows, q=q, cat=cat, loc=loc, show=show, cats=cats, locs=locs)


def form_asset():
    f = request.form
    qty = max(int(f.get("quantity") or 1), 0)
    return dict(name=f["name"].strip(), category_id=int(f["category_id"]),
                location_id=int(f["location_id"]) if f.get("location_id") else None,
                serial_number=f.get("serial_number", "").strip() or None,
                isbn=f.get("isbn", "").strip() or None,
                author_brand=f.get("author_brand", "").strip() or None,
                quantity=qty, condition=f.get("condition", "Good"), notes=f.get("notes", "").strip() or None)


@app.route("/assets/new", methods=["GET", "POST"])
@login_required
def asset_new():
    cats, locs = lookups()
    if request.method == "POST":
        v = form_asset()
        cat = db().execute("SELECT * FROM categories WHERE id = ?", (v["category_id"],)).fetchone()
        if not v["name"]:
            flash("Name is required.", "error")
            return render_template("asset_form.html", a=v, cats=cats, locs=locs, new=True)
        if not cat["bulk"]:
            v["quantity"] = 1  # serialised items: one record per physical unit
        try:
            cur = db().execute("""INSERT INTO assets(name, category_id, location_id, serial_number, isbn,
                author_brand, quantity, condition, notes, created_at) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (v["name"], v["category_id"], v["location_id"], v["serial_number"], v["isbn"],
                 v["author_brand"], v["quantity"], v["condition"], v["notes"],
                 datetime.now().isoformat(" ", "seconds")))
            aid = cur.lastrowid
            code = f"{cat['prefix']}-{aid:06d}"
            db().execute("UPDATE assets SET asset_code = ? WHERE id = ?", (code, aid))
            log("asset registered", f"{code} {v['name']} x{v['quantity']}")
            db().commit()
        except sqlite3.IntegrityError as e:
            db().rollback()
            flash(f"Could not save: {e}", "error")
            return render_template("asset_form.html", a=v, cats=cats, locs=locs, new=True)
        flash(f"Registered {code}. Print its label below.", "ok")
        return redirect(url_for("asset_detail", asset_id=aid))
    return render_template("asset_form.html", a={"quantity": 1, "condition": "Good"}, cats=cats, locs=locs, new=True)


@app.route("/assets/<int:asset_id>")
@login_required
def asset_detail(asset_id):
    a = get_asset(asset_id)
    if not a:
        abort(404)
    d = db()
    open_ = d.execute("SELECT a.*, " + RECIPIENT_SQL + " AS who FROM assignments a "
                      "WHERE asset_id = ? AND status = 'Issued' ORDER BY issue_date", (asset_id,)).fetchall()
    hist = d.execute("""SELECT a.*, """ + RECIPIENT_SQL + """ AS who, r.return_date, r.condition rcond
        FROM assignments a LEFT JOIN returns r ON r.assignment_id = a.id
        WHERE asset_id = ? AND status = 'Returned' ORDER BY r.return_date DESC LIMIT 50""", (asset_id,)).fetchall()
    maint = d.execute("SELECT * FROM maintenance WHERE asset_id = ? ORDER BY reported_date DESC", (asset_id,)).fetchall()
    return render_template("asset_detail.html", a=a, open_=open_, hist=hist, maint=maint)


@app.route("/assets/<int:asset_id>/edit", methods=["GET", "POST"])
@login_required
def asset_edit(asset_id):
    a = get_asset(asset_id)
    if not a:
        abort(404)
    cats, locs = lookups()
    if request.method == "POST":
        v = form_asset()
        if not a["bulk"]:
            v["quantity"] = 1
        if v["quantity"] < a["assigned"] + a["damaged_qty"]:
            flash("Quantity can't be lower than units currently assigned or damaged "
                  f"({a['assigned'] + a['damaged_qty']}).", "error")
            return render_template("asset_form.html", a={**dict(a), **v}, cats=cats, locs=locs, new=False)
        try:
            db().execute("""UPDATE assets SET name=?, category_id=?, location_id=?, serial_number=?, isbn=?,
                author_brand=?, quantity=?, condition=?, notes=? WHERE id=?""",
                (v["name"], a["category_id"], v["location_id"], v["serial_number"], v["isbn"],
                 v["author_brand"], v["quantity"], v["condition"], v["notes"], asset_id))
            log("asset edited", a["asset_code"])
            db().commit()
        except sqlite3.IntegrityError as e:
            db().rollback()
            flash(f"Could not save: {e}", "error")
            return render_template("asset_form.html", a={**dict(a), **v}, cats=cats, locs=locs, new=False)
        flash("Asset updated.", "ok")
        return redirect(url_for("asset_detail", asset_id=asset_id))
    return render_template("asset_form.html", a=a, cats=cats, locs=locs, new=False)


@app.route("/assets/<int:asset_id>/retire", methods=["POST"])
@admin_required
def asset_retire(asset_id):
    """Assets are never hard-deleted (history must stay); they're retired, and only if nothing is out."""
    a = get_asset(asset_id)
    if not a:
        abort(404)
    if a["assigned"] > 0:
        flash("This asset still has units assigned. Record their return first.", "error")
    else:
        db().execute("UPDATE assets SET active = ? WHERE id = ?", (0 if a["active"] else 1, asset_id))
        log("asset retired" if a["active"] else "asset restored", a["asset_code"])
        db().commit()
        flash("Asset retired." if a["active"] else "Asset restored.", "ok")
    return redirect(url_for("asset_detail", asset_id=asset_id))


@app.route("/labels")
@login_required
def labels():
    ids = [int(i) for i in request.args.getlist("id") if i.isdigit()]
    if not ids:
        flash("Tick at least one asset to print labels.", "error")
        return redirect(url_for("assets"))
    marks = ",".join("?" * len(ids))
    rows = db().execute(ASSET_SQL + f" WHERE id IN ({marks}) ORDER BY asset_code", ids).fetchall()
    copies = max(1, min(int(request.args.get("copies", 1) or 1), 50))
    return render_template("labels.html", rows=rows, copies=copies)


# ------------------------------------------------------------------ people
@app.route("/people", methods=["GET", "POST"])
@login_required
def people():
    d = db()
    if request.method == "POST":
        f = request.form
        try:
            if f["kind"] == "student":
                d.execute("INSERT INTO students(admission_no, name, class_name) VALUES(?,?,?)",
                          (f["number"].strip(), f["name"].strip(), f.get("extra", "").strip()))
            else:
                d.execute("INSERT INTO staff(staff_no, name, department) VALUES(?,?,?)",
                          (f["number"].strip(), f["name"].strip(), f.get("extra", "").strip()))
            log(f"{f['kind']} added", f"{f['number']} {f['name']}")
            d.commit()
            flash("Saved.", "ok")
        except sqlite3.IntegrityError:
            d.rollback()
            flash("That admission/staff number already exists.", "error")
        return redirect(url_for("people"))
    q = request.args.get("q", "").strip()
    like = f"%{q}%"
    students = d.execute("SELECT * FROM students WHERE name LIKE ? OR admission_no LIKE ? ORDER BY name LIMIT 300",
                         (like, like)).fetchall()
    staff = d.execute("SELECT * FROM staff WHERE name LIKE ? OR staff_no LIKE ? ORDER BY name LIMIT 300",
                      (like, like)).fetchall()
    return render_template("people.html", students=students, staff=staff, q=q)


@app.route("/people/import", methods=["POST"])
@login_required
def people_import():
    """CSV columns: number,name,class_or_department   (no header needed; header row is skipped if it says 'number')."""
    kind = request.form["kind"]
    file = request.files.get("file")
    if not file:
        flash("Choose a CSV file.", "error")
        return redirect(url_for("people"))
    text = file.read().decode("utf-8-sig", errors="replace")
    added = skipped = 0
    for i, row in enumerate(csv.reader(io.StringIO(text))):
        if len(row) < 2 or (i == 0 and row[0].strip().lower() in ("number", "admission_no", "staff_no")):
            continue
        extra = row[2].strip() if len(row) > 2 else ""
        try:
            if kind == "student":
                db().execute("INSERT INTO students(admission_no, name, class_name) VALUES(?,?,?)",
                             (row[0].strip(), row[1].strip(), extra))
            else:
                db().execute("INSERT INTO staff(staff_no, name, department) VALUES(?,?,?)",
                             (row[0].strip(), row[1].strip(), extra))
            added += 1
        except sqlite3.IntegrityError:
            skipped += 1
    log(f"{kind} import", f"{added} added, {skipped} duplicates skipped")
    db().commit()
    flash(f"Imported {added}; skipped {skipped} duplicates.", "ok")
    return redirect(url_for("people"))


@app.route("/api/person")
@login_required
def api_person():
    kind, num = request.args.get("type"), request.args.get("number", "").strip()
    if kind == "student":
        r = db().execute("SELECT id, name, class_name AS extra FROM students WHERE admission_no = ? COLLATE NOCASE", (num,)).fetchone()
    else:
        r = db().execute("SELECT id, name, department AS extra FROM staff WHERE staff_no = ? COLLATE NOCASE", (num,)).fetchone()
    return jsonify(dict(r) if r else {})


@app.route("/api/asset")
@login_required
def api_asset():
    a = find_asset_by_scan(request.args.get("code"))
    if not a:
        return jsonify({})
    return jsonify({k: a[k] for k in ("id", "asset_code", "name", "category", "location", "quantity",
                                      "assigned", "damaged_qty", "available", "bulk")})


# ------------------------------------------------------------------ issue
@app.route("/issue", methods=["GET", "POST"])
@login_required
def issue():
    d = db()
    if request.method == "POST":
        f = request.form
        a = find_asset_by_scan(f.get("asset_code"))
        kind = f.get("recipient_type")
        num = f.get("recipient_no", "").strip()
        qty = int(f.get("qty") or 1)
        issue_date = f.get("issue_date") or date.today().isoformat()
        due = f.get("due_date") or None
        err = None
        person = None
        if not a:
            err = "No active asset matches that code."
        elif kind not in ("student", "staff"):
            err = "Choose whether the recipient is a student or staff member."
        else:
            person = d.execute(
                "SELECT id, name FROM students WHERE admission_no = ? COLLATE NOCASE" if kind == "student"
                else "SELECT id, name FROM staff WHERE staff_no = ? COLLATE NOCASE", (num,)).fetchone()
            if not person:
                err = "Recipient not found. Register them under People first."
            elif qty < 1:
                err = "Quantity must be at least 1."
            elif qty > a["available"]:
                err = f"Only {a['available']} unit(s) of {a['name']} available."
            elif due and due < issue_date:
                err = "Due date can't be before the issue date."
        if err:
            flash(err, "error")
            return render_template("issue.html", f=f)
        d.execute("""INSERT INTO assignments(asset_id, recipient_type, recipient_id, qty, issue_date, due_date,
                     issued_by, notes) VALUES(?,?,?,?,?,?,?,?)""",
                  (a["id"], kind, person["id"], qty, issue_date, due, session["uid"], f.get("notes") or None))
        log("asset issued", f"{a['asset_code']} x{qty} to {person['name']} ({num})")
        d.commit()
        flash(f"Issued {qty} x {a['name']} to {person['name']}.", "ok")
        return redirect(url_for("issue"))
    return render_template("issue.html", f={})


# ----------------------------------------------------------------- returns
@app.route("/returns", methods=["GET", "POST"])
@login_required
def returns():
    d = db()
    if request.method == "POST":
        f = request.form
        a_ = d.execute("SELECT * FROM assignments WHERE id = ? AND status = 'Issued'", (f.get("assignment_id"),)).fetchone()
        if not a_:
            flash("That assignment is already closed or doesn't exist.", "error")
            return redirect(url_for("returns"))
        bad = max(0, min(int(f.get("damaged_qty") or 0), a_["qty"]))
        ret_date = f.get("return_date") or date.today().isoformat()
        cond = "Damaged" if bad else f.get("condition", "Good")
        d.execute("UPDATE assignments SET status = 'Returned' WHERE id = ?", (a_["id"],))
        d.execute("""INSERT INTO returns(assignment_id, return_date, damaged_qty, condition, notes, received_by)
                     VALUES(?,?,?,?,?,?)""",
                  (a_["id"], ret_date, bad, cond, f.get("notes") or None, session["uid"]))
        asset = d.execute("SELECT asset_code FROM assets WHERE id = ?", (a_["asset_id"],)).fetchone()
        if bad:
            d.execute("UPDATE assets SET damaged_qty = damaged_qty + ? WHERE id = ?", (bad, a_["asset_id"]))
            d.execute("""INSERT INTO maintenance(asset_id, qty, issue, reported_date, reported_by)
                         VALUES(?,?,?,?,?)""",
                      (a_["asset_id"], bad, f.get("notes") or "Returned damaged", ret_date, session["uid"]))
        log("asset returned", f"{asset['asset_code']} x{a_['qty']} ({bad} damaged)")
        d.commit()
        flash("Return recorded." + (f" {bad} unit(s) flagged as damaged." if bad else ""), "ok")
        return redirect(url_for("returns", q=request.args.get("q", "")))
    q = request.args.get("q", "").strip()
    base = """SELECT a.*, s.name asset_name, s.asset_code, """ + RECIPIENT_SQL + """ AS who
              FROM assignments a JOIN assets s ON s.id = a.asset_id WHERE a.status = 'Issued'"""
    args = []
    if q:
        # match asset code/serial/ISBN, or recipient number/name
        base += """ AND (s.asset_code = ? COLLATE NOCASE OR s.serial_number = ? COLLATE NOCASE OR s.isbn = ?
            OR s.name LIKE ? OR (a.recipient_type='student' AND a.recipient_id IN
                (SELECT id FROM students WHERE admission_no = ? COLLATE NOCASE OR name LIKE ?))
            OR (a.recipient_type='staff' AND a.recipient_id IN
                (SELECT id FROM staff WHERE staff_no = ? COLLATE NOCASE OR name LIKE ?)))"""
        args = [q, q, q, f"%{q}%", q, f"%{q}%", q, f"%{q}%"]
    rows = d.execute(base + " ORDER BY a.due_date IS NULL, a.due_date, a.issue_date LIMIT 200", args).fetchall()
    return render_template("returns.html", rows=rows, q=q)


# ------------------------------------------------------------- maintenance
@app.route("/maintenance", methods=["GET", "POST"])
@login_required
def maintenance():
    d = db()
    if request.method == "POST":
        f = request.form
        a = find_asset_by_scan(f.get("asset_code"))
        qty = int(f.get("qty") or 1)
        if not a:
            flash("No active asset matches that code.", "error")
        elif qty < 1 or qty > a["available"]:
            flash(f"Only {a['available']} unit(s) are free to flag (assigned units must be returned first).", "error")
        elif not f.get("issue", "").strip():
            flash("Describe the problem.", "error")
        else:
            d.execute("UPDATE assets SET damaged_qty = damaged_qty + ? WHERE id = ?", (qty, a["id"]))
            d.execute("""INSERT INTO maintenance(asset_id, qty, issue, reported_date, reported_by)
                         VALUES(?,?,?,?,?)""", (a["id"], qty, f["issue"].strip(), date.today().isoformat(), session["uid"]))
            log("damage reported", f"{a['asset_code']} x{qty}: {f['issue'].strip()}")
            d.commit()
            flash("Flagged as damaged.", "ok")
        return redirect(url_for("maintenance"))
    status = request.args.get("status", "Open")
    sql = """SELECT m.*, a.name asset_name, a.asset_code FROM maintenance m JOIN assets a ON a.id = m.asset_id"""
    rows = d.execute(sql + (" WHERE m.status = 'Open'" if status == "Open" else "") +
                     " ORDER BY m.reported_date DESC LIMIT 300").fetchall()
    return render_template("maintenance.html", rows=rows, status=status)


@app.route("/maintenance/<int:mid>/resolve", methods=["POST"])
@login_required
def maintenance_resolve(mid):
    d = db()
    m = d.execute("SELECT * FROM maintenance WHERE id = ? AND status = 'Open'", (mid,)).fetchone()
    if not m:
        abort(404)
    outcome = request.form.get("outcome")
    if outcome not in ("Repaired", "Written off"):
        abort(400)
    cost = request.form.get("cost")
    d.execute("UPDATE maintenance SET status=?, resolved_date=?, cost=?, notes=? WHERE id=?",
              (outcome, date.today().isoformat(), float(cost) if cost else None, request.form.get("notes") or None, mid))
    d.execute("UPDATE assets SET damaged_qty = damaged_qty - ? WHERE id = ?", (m["qty"], m["asset_id"]))
    if outcome == "Written off":
        d.execute("UPDATE assets SET quantity = quantity - ? WHERE id = ?", (m["qty"], m["asset_id"]))
    log(f"maintenance {outcome.lower()}", f"record {mid}")
    d.commit()
    flash(f"Marked {outcome.lower()}.", "ok")
    return redirect(url_for("maintenance"))


# ----------------------------------------------------------------- reports
def csv_response(name, header, rows):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    w.writerows(rows)
    return Response("\ufeff" + buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={name}-{date.today()}.csv"})


REPORTS = {
    "inventory": ("Inventory", ["Code", "Name", "Category", "Location", "Serial", "ISBN", "Total",
                                "Assigned", "Damaged", "Available", "Condition"]),
    "assignments": ("Current assignments", ["Code", "Asset", "Recipient", "Qty", "Issued", "Due", "Overdue"]),
    "overdue": ("Overdue returns", ["Code", "Asset", "Recipient", "Qty", "Issued", "Due", "Days overdue"]),
    "history": ("Assignment history", ["Code", "Asset", "Recipient", "Qty", "Issued", "Returned", "Condition"]),
}


def report_rows(kind):
    d, t = db(), date.today().isoformat()
    if kind == "inventory":
        return [(r["asset_code"], r["name"], r["category"], r["location"], r["serial_number"], r["isbn"],
                 r["quantity"], r["assigned"], r["damaged_qty"], r["available"], r["condition"])
                for r in d.execute(ASSET_SQL + " WHERE active = 1 ORDER BY category, name")]
    base = """SELECT s.asset_code, s.name, """ + RECIPIENT_SQL + """ who, a.qty, a.issue_date, a.due_date,
              r.return_date, r.condition FROM assignments a JOIN assets s ON s.id = a.asset_id
              LEFT JOIN returns r ON r.assignment_id = a.id"""
    if kind == "assignments":
        return [(r[0], r[1], r[2], r[3], r[4], r[5] or "", "Yes" if r[5] and r[5] < t else "")
                for r in d.execute(base + " WHERE a.status='Issued' ORDER BY a.issue_date")]
    if kind == "overdue":
        out = []
        for r in d.execute(base + " WHERE a.status='Issued' AND a.due_date IS NOT NULL AND a.due_date < ? "
                                  "ORDER BY a.due_date", (t,)):
            out.append((r[0], r[1], r[2], r[3], r[4], r[5], (date.today() - date.fromisoformat(r[5])).days))
        return out
    return [(r[0], r[1], r[2], r[3], r[4], r[6], r[7])
            for r in d.execute(base + " WHERE a.status='Returned' ORDER BY r.return_date DESC")]


@app.route("/reports")
@login_required
def reports():
    return render_template("reports.html", reports=REPORTS)


@app.route("/reports/<kind>")
@login_required
def report(kind):
    if kind not in REPORTS:
        abort(404)
    title, header = REPORTS[kind]
    rows = report_rows(kind)
    if request.args.get("format") == "csv":
        return csv_response(kind, header, rows)
    return render_template("report.html", kind=kind, title=title, header=header, rows=rows)


@app.route("/logs")
@login_required
def logs():
    q = request.args.get("q", "").strip()
    rows = db().execute("""SELECT * FROM activity_logs WHERE action LIKE ? OR details LIKE ? OR username LIKE ?
                           ORDER BY id DESC LIMIT 300""", (f"%{q}%",) * 3).fetchall()
    return render_template("logs.html", rows=rows, q=q)


@app.route("/scan")
@login_required
def scan():
    return render_template("scan.html")


# ------------------------------------------------------------------- users
@app.route("/users", methods=["GET", "POST"])
@admin_required
def users():
    d = db()
    if request.method == "POST":
        f = request.form
        if len(f["password"]) < 8:
            flash("Password must be at least 8 characters.", "error")
        elif f["role"] not in ROLES:
            abort(400)
        else:
            try:
                d.execute("INSERT INTO users(username, full_name, password_hash, role) VALUES(?,?,?,?)",
                          (f["username"].strip(), f["full_name"].strip(), generate_password_hash(f["password"]), f["role"]))
                log("user created", f["username"])
                d.commit()
                flash("User created.", "ok")
            except sqlite3.IntegrityError:
                d.rollback()
                flash("Username already exists.", "error")
        return redirect(url_for("users"))
    return render_template("users.html", rows=d.execute("SELECT * FROM users ORDER BY username").fetchall(), roles=ROLES)


@app.route("/users/<int:uid>/toggle", methods=["POST"])
@admin_required
def user_toggle(uid):
    if uid == session["uid"]:
        flash("You can't deactivate your own account.", "error")
    else:
        db().execute("UPDATE users SET active = 1 - active WHERE id = ?", (uid,))
        log("user toggled", str(uid))
        db().commit()
    return redirect(url_for("users"))


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    if request.method == "POST":
        u = db().execute("SELECT * FROM users WHERE id = ?", (session["uid"],)).fetchone()
        if not check_password_hash(u["password_hash"], request.form["current"]):
            flash("Current password is wrong.", "error")
        elif len(request.form["new"]) < 8:
            flash("New password must be at least 8 characters.", "error")
        else:
            db().execute("UPDATE users SET password_hash = ? WHERE id = ?",
                         (generate_password_hash(request.form["new"]), u["id"]))
            log("password changed")
            db().commit()
            flash("Password changed.", "ok")
            return redirect(url_for("dashboard"))
    return render_template("account.html")


init_db()

if __name__ == "__main__":
    # host 0.0.0.0 lets other computers/phones on the school network reach it.
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
