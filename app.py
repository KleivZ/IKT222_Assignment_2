# app.py
import os
import base64
import sqlite3
from io import BytesIO
from dotenv import load_dotenv # Use pip install python-dotenv
from flask import Flask, render_template, request, g, redirect, session, url_for, flash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from google_auth_oauthlib.flow import Flow
import bcrypt
import pyotp
import qrcode
import bleach
import requests
import logging

load_dotenv('my_little_secrets.env')  # Load environment variables from .env file

# App Setup and Configuration
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))  # For session handling, prefer environment variable

# Client and OAuth Configuration
CLIENT_ID = os.environ.get("CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
REDIRECT_URI=os.environ.get("REDIRECT_URI")
GOOGLE_AUTH_URL=os.getenv("GOOGLE_AUTH_URL")
GOOGLE_TOKEN_URL=os.getenv("GOOGLE_TOKEN_URL")
GOOGLE_USER_INFO_URL=os.getenv("GOOGLE_USER_INFO_URL")

# Temporary storage for auth and tokens (Use a proper database in production)
AUTH_CODES = {}
TOKENS = {}

# Initialize Flask-Limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    app=app
)

# Google OAuth2 Flow
flow = Flow.from_client_config(
    {
        "web": {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "redirect_uris": [REDIRECT_URI],
        }
    },
    scopes=[
        'openid',
        'https://www.googleapis.com/auth/userinfo.email',
        'https://www.googleapis.com/auth/userinfo.profile'
    ]
)

# Cookie settings for session security
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production

# Database Configuration
DATABASE = 'database.db'

# Logging Configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Content Security Policy
@app.after_request
def apply_csp(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' https://code.jquery.com https://cdn.jsdelivr.net https://stackpath.bootstrapcdn.com; "
        "style-src 'self' https://stackpath.bootstrapcdn.com; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'self'"
    )
    return response

# Database Connection Handling
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception=None):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

# Authentication Routes
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("3 per minute")
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"].encode('utf-8')
        user = query_db('SELECT * FROM users WHERE username = ?', [username], one=True)

        if user and bcrypt.checkpw(password, user['password']):
            session['user_id'] = user['id']
            return redirect('/')
        else:
            error = 'Ugyldig brukernavn eller passord'
            return render_template('login.html', error=error)
    return render_template('login.html')

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("3 per minute")
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if password != confirm_password:
            error = 'Passordene matcher ikke'
            return render_template('register.html', error=error)

        if not validate_password(password):
            error = 'Passordet må være minst 8 tegn langt og inneholde minst ett tall og ett spesialtegn.'
            return render_template('register.html', error=error)

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        try:
            totp_secret = pyotp.random_base32()
            totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name='Min Blogg')
            img = qrcode.make(totp_uri)
            buffered = BytesIO()
            img.save(buffered, format="PNG")
            totp_qr_code = "data:image/png;base64," + base64.b64encode(buffered.getvalue()).decode('utf-8')

            get_db().execute('INSERT INTO users (username, password, totp_secret) VALUES (?, ?, ?)',
                             [username, hashed_password, totp_secret])
            get_db().commit()

            return render_template('register.html', totp_qr_code=totp_qr_code)
        except sqlite3.IntegrityError:
            error = 'Brukernavnet er allerede i bruk.'
            return render_template('register.html', error=error)
        except Exception as e:
            logger.error(f"Database error during registration: {e}")
            error = 'Noe gikk galt under registreringen'
            return render_template('register.html', error=error)
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('user_email', None)
    session.clear()
    return redirect(url_for('index'))

@app.route('/verify_2fa/<username>', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
def verify_2fa(username):
    if request.method == 'POST':
        code = request.form['2fa_code']
        user = query_db('SELECT * FROM users WHERE username = ?', [username], one=True)
        if user:
            totp = pyotp.TOTP(user['totp_secret'])
            if totp.verify(code):
                session['user_id'] = user['id']
                return redirect('/')
            else:
                error = 'Ugyldig 2FA-kode'
                return render_template('two_factor_auth.html', username=username, error=error)
    return render_template('two_factor_auth.html', username=username)

@app.route("/google_auth")
def google_auth():
    google_auth_url = (
        f"{GOOGLE_AUTH_URL}?response_type=code"
        f"&client_id={CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        f"&scope=email profile"
        f"&access_type=offline"
        f"&prompt=select_account"
    )
    return redirect(google_auth_url)

@app.route("/google_callback")
def google_callback():
    try:
        code = request.args.get("code")
        if not code:
            flash("Authorization failed. Missing code parameter.", "error")
            return redirect(url_for("login"))

        token_data = {
            "code": code,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "redirect_uri": REDIRECT_URI,
            "grant_type": "authorization_code",
        }
        token_response = requests.post(GOOGLE_TOKEN_URL, data=token_data)
        token_response.raise_for_status()

        token_json = token_response.json()
        access_token = token_json.get("access_token")
        if not access_token:
            flash("Failed to retrieve access token.", "error")
            return redirect(url_for("login"))

        user_info_response = requests.get(
            GOOGLE_USER_INFO_URL,
            headers={"Authorization": f"Bearer {access_token}"}
        )
        user_info_response.raise_for_status()

        user_info = user_info_response.json()
        user_email = user_info.get("email")
        if not user_email:
            flash("Failed to retrieve email.", "error")
            return redirect(url_for("login"))

        user = find_user_by_email(user_email)
        if not user:
            add_google_user(user_email)

        session["user_email"] = user_email
        return redirect(url_for("index"))
    except requests.RequestException as e:
        logger.error(f"OAuth error: {e}")
        flash("An error occurred during Google authentication.", "error")
        return redirect(url_for("login"))

# Helper Functions and Main Execution
def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def get_user():
    user_id = session.get('user_id')
    if user_id:
        user = query_db('SELECT * FROM users WHERE id = ?', [user_id], one=True)
        if user:
            return user['username']
    user_email = session.get('user_email')
    if user_email:
        return user_email
    return None

@app.context_processor
def inject_user():
    return dict(user=get_user())

def find_user_by_email(user_email):
    return query_db('SELECT * FROM users WHERE username = ?', [user_email], one=True)

def add_google_user(user_email, oauth_provider="google", oauth_user_id=None):
    db = get_db()
    db.execute(
        'INSERT INTO users (username, password, oauth_provider, oauth_user_id) VALUES (?, ?, ?, ?)',
        [user_email, "", oauth_provider, oauth_user_id]
    )
    db.commit()

def validate_password(password):
    if len(password) < 8:
        return False
    if not any(char.isdigit() for char in password):
        return False
    if not any(not char.isalnum() for char in password):
        return False
    return True

@app.route("/", methods=["GET", "POST"])
def index():
    db = get_db()
    cursor = db.cursor()
    if request.method == "POST":
        comment = request.form["comment"]
        sanitized_comment = bleach.linkify(bleach.clean(comment))
        cursor.execute("INSERT INTO comments (content) VALUES (?)", (sanitized_comment,))
        db.commit()
    cursor.execute("SELECT content FROM comments ORDER BY created_at DESC")
    comments = [row[0] for row in cursor.fetchall()]
    return render_template("index.html", comments=comments)

@app.route("/om_meg")
def om_meg():
    return render_template("om_meg.html")

@app.route('/kontakt', methods=['GET', 'POST'])
def kontakt():
    if request.method == 'POST':
        return "Thank you for your message!"
    return render_template('kontakt.html')

@app.errorhandler(429)
def ratelimit_handler(exception):
    error_message = "For mange innloggingsforsøk. Vennligst prøv igjen om et minutt."
    return render_template("login.html", error=error_message), 429

if __name__ == "__main__":
    init_db()
    app.run(debug=True, host='0.0.0.0')
