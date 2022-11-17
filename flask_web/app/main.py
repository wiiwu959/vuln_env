from flask import Flask, flash, session, make_response, render_template, redirect, request, g, url_for
from flask_session import Session
import sqlite3, time, re, os, pickle, html
from base64 import b64encode, b64decode
import urllib.request
from redis import Redis

from secret import SECRET

app = Flask(__name__)
# A05 Security Misconfiguration
app.config.update(SESSION_COOKIE_HTTPONLY=False)
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = Redis(host='127.0.0.1', port=6379)
# A02 Cryptographic Failures (using fix session key)
app.config['SECRET_KEY'] = SECRET
app.secret_key = SECRET
Session(app)

DATABASE = "database.db"
users = {"admin": "password123", "user1": "CrYp70graphiC_F@i1ure2"}

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.execute("PRAGMA foreign_keys = ON")
    return db

@app.before_first_request
def init_db():
    with app.app_context():
        db = get_db()
        db.cursor().execute('''
        CREATE TABLE IF NOT EXISTS "users" (
            "username" TEXT NOT NULL,
            "password" TEXT NOT NULL
        )
        ''')
        cur = db.cursor().execute("SELECT * FROM users")
        res = cur.fetchall()
        if not res:
            for key, value in users.items():
                # base64 -> bad encoding
                insert_val = b64encode(value.encode()).decode()
                db.cursor().execute(f"INSERT INTO users (username, password) VALUES (?, ?)", (key, insert_val))
        db.commit()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# ======= Login =======
# SQL Injection
@app.route("/login", methods=['POST'])
def login():
    db = get_db()
    username = request.form.get('username')
    password = request.form.get('password')
    
    if not username or not password:
        flash('You were failed logged in', 'error')
        return redirect(url_for("index"))

    # TODO 可以拿出來改
    # admin') OR 1=1--
    cur = db.execute(f"SELECT * FROM users WHERE (username='{username}') AND (password='{b64encode(password.encode()).decode()}')")
    res = cur.fetchone()
    cur.close()

    if res:
        session["user"] = "admin"
        return redirect(url_for("index"))

    flash('You were failed logged in', 'error')
    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    session["user"] = "guest"
    return redirect(url_for("index"))

@app.route("/index")
def index():
    if not session or "user" not in session or session["user"] == "guest":
        session["user"] = "guest"
        return render_template("login.html")

    if session["user"] == "admin":
        return render_template("admin.html")

# ======= Cat Notes =======
@app.route("/show")
def show():
    cookie = request.cookies.get("cat_info")
    if not cookie:
        return render_template("cat_list.html")
    
    cat_info = pickle.loads(b64decode(cookie))
    if "cat" not in cat_info:
        return render_template("cat_list.html")

    param = str(cat_info["cat"])
    # Permissive List of Allowed Inputs
    if re.search("^../app", param):
        return "Invalid!"
    param = param.replace("../", "")
    requested_path = "/app/cats/" + param

    try:
        # command injection
        output = os.popen(f"cat {requested_path}").read()
    except Exception as e:
        return "No This Cat"
    return render_template("cat_note.html", output=output)


@app.route("/cats")
def cats():
    return render_template("cat_list.html")

@app.route("/bake")
def bake():
    param = request.args.get('cat')
    cat_info = {"cat": param}
    cat_info = b64encode(pickle.dumps(cat_info)).decode()
    
    resp = make_response(redirect(url_for("show")))
    resp.set_cookie(key="cat_info", value=cat_info, expires=time.time()+6*60)
    return resp

# ======= SSRF =======
# TODO: make this ssrf more reasonable
# http://127.0.0.1:8001/ssrf?url=http://127.0.0.1:6379?%0d%0aSET%20B%20bbb%0d%0apadding
@app.route("/lookup")
def url_lookup():
    url = request.args.get('url')
    if not url:
        return render_template("url_check.html", info="Enter url and fetch source")
    
    try:
        info = urllib.request.urlopen(url)
    except:
        return render_template("wrong.html")
    return render_template("url_check.html", info=info.read().decode())

@app.route("/")
def home():
    return render_template("home.html")

if __name__ == "__main__":
    # Only for debugging while developing
    app.run(host="0.0.0.0", debug=True, port=80)
