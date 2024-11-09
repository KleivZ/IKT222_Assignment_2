import os
import base64
import sqlite3
import bcrypt
import pyotp
import qrcode
import bleach
import requests
import secrets
import datetime
from itsdangerous import URLSafeSerializer, BadSignature, BadData
from io import BytesIO
from dotenv import load_dotenv
from flask_session import Session
from flask import Flask, render_template, request, g, redirect, session, url_for, flash, make_response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from google_auth_oauthlib.flow import Flow
from cryptography.fernet import Fernet

# Load environment variables
load_dotenv('my_little_secrets.env')

# Initialize Flask app and secure session key
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))  # Random fallback for extra security

# Set up serializer with secret key
serializer = URLSafeSerializer(app.secret_key)

# Set up persistent sessions
session_folder = os.path.join(os.getcwd(), 'flask_session')
if not os.path.exists(session_folder):
    os.makedirs(session_folder)

app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_PERMANENT"] = True
app.config['SESSION_FILE_DIR'] = session_folder
app.config['SESSION_COOKIE_NAME'] = 'session_id'

# Initialize session management
Session(app)

# OAuth2 client and redirect configuration
CLIENT_ID = os.environ.get("CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
REDIRECT_URI = os.environ.get("REDIRECT_URI")
GOOGLE_AUTH_URL = os.getenv("GOOGLE_AUTH_URL")
GOOGLE_TOKEN_URL = os.getenv("GOOGLE_TOKEN_URL")
GOOGLE_USER_INFO_URL = os.getenv("GOOGLE_USER_INFO_URL")

# Load encryption key from environment variables
encryption_key = os.environ.get('ENCRYPTION_KEY')

# Provide encryption key for database encryption
cipher_suite = Fernet(encryption_key)

# Flask-Limiter setup for rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    app=app
)

# OAuth2 flow setup with Google configuration
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

# Session cookie settings to protect against common web attacks
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to cookies
app.config['SESSION_COOKIE_SECURE'] = True  # Requires HTTPS in production
app.config['SESSION_COOKIE_SAMESITE'] = 'None'

# Database path
DATABASE = 'database.db'

# Applying Content Security Policy (CSP)
@app.after_request
def apply_csp(response):
    script_nonce = session.get('script_nonce', '')
    csp = (
        "default-src 'self'; "
        f"script-src 'nonce-{script_nonce}' 'self' https://code.jquery.com https://cdn.jsdelivr.net "
        f"https://stackpath.bootstrapcdn.com; "
        "style-src 'self' https://stackpath.bootstrapcdn.com; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'self'"
    )
    response.headers['Content-Security-Policy'] = csp
    session.pop('script_nonce', None)
    return response


# Connect to database and enable row access by column names
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


# Close the database connection after each request
@app.teardown_appcontext
def close_connection(exception=None):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


# Initialize database schema
def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()


# Sanitize input
def sanitize_input(input_data):
    return bleach.clean(input_data, tags=[], attributes={}, strip=True)


# Generate a secure "remember me" token
def generate_remember_token():
    return secrets.token_urlsafe(32)


# Check for presence of valid remember-me token
def is_device_remembered(user_id):
    remember_token = request.cookies.get('remember_token')
    if remember_token:
        stored_token = query_db("SELECT remember_token FROM users WHERE id = ?", [user_id], one=True)
        return stored_token and stored_token['remember_token'] == remember_token
    return False


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"].encode('utf-8')  # Encode entered password as bytes
        user = query_db("SELECT * FROM users WHERE username = ?", [username], one=True)
        if user:
            try:
                stored_password = user['password']
                if isinstance(stored_password, str):
                    stored_password = stored_password.encode('utf-8')
                # Check password with bcrypt
                if bcrypt.checkpw(password, stored_password):
                    # Check if the device is remembered and skip 2FA if it is
                    if is_device_remembered(user['id']):
                        session['user_id'] = user['id']
                        return redirect(url_for("index"))
                    # If not remembered, set pending_user_id and redirect to 2FA
                    session['pending_user_id'] = user['id']
                    return render_template("two_factor_auth.html")
                else:
                    # Flash error message for wrong password
                    flash("Invalid username/password.", "failure")
                    return redirect(url_for("login"))
            except ValueError:
                flash("Invalid username/password.", "failure")
                return redirect(url_for("login"))
        else:
            # Flash error message for invalid username
            flash("Invalid username/password.", "failure")
            return redirect(url_for("login"))
    return render_template("login.html")


@app.route("/two_factor_auth", methods=["POST"])
def two_factor_auth():
    pending_user_id = session.get('pending_user_id')
    if not pending_user_id:
        return redirect(url_for("login"))
    user = query_db("SELECT * FROM users WHERE id = ?", [pending_user_id], one=True)
    totp_code = request.form.get("2fa_code")
    # Decrypt and verify the TOTP secret
    encrypted_totp_secret = base64.b64decode(user['totp_secret'])
    totp_secret = cipher_suite.decrypt(encrypted_totp_secret).decode()
    totp = pyotp.TOTP(totp_secret)
    if totp.verify(totp_code):
        session.pop('pending_user_id', None)
        session['user_id'] = user['id']
        # If "Remember this device" is checked, set a persistent cookie
        if 'remember_me' in request.form:
            remember_token = generate_remember_token()
            get_db().execute('UPDATE users SET remember_token = ? WHERE id = ?', (remember_token, user['id']))
            get_db().commit()
            response = make_response(redirect(url_for("index")))
            response.set_cookie('remember_token', remember_token, max_age=30 * 24 * 60 * 60, secure=True, httponly=True)
            return response
        else:
            return redirect(url_for("index"))
    else:
        error = "Invalid 2FA code. Please try again."
        return render_template("two_factor_auth.html", error=error)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if 'username' in request.form and 'password' in request.form and 'confirm_password' in request.form:
            username = sanitize_input(request.form["username"])
            # Remove sanitation on password and confirm_password before hashing
            password = request.form["password"]
            confirm_password = request.form["confirm_password"]
            if password != confirm_password:
                return render_template('register.html', error="Passwords do not match")
            if not validate_password(password):
                return render_template('register.html', error="Password must meet complexity requirements")
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            totp_secret = pyotp.random_base32()
            encrypted_totp_secret = cipher_suite.encrypt(totp_secret.encode())
            encrypted_totp_secret_b64 = base64.b64encode(encrypted_totp_secret).decode()
            try:
                get_db().execute('INSERT INTO users (username, password, totp_secret) VALUES (?, ?, ?)',
                                 [username, hashed_password, encrypted_totp_secret_b64])
                get_db().commit()
            except sqlite3.IntegrityError:
                return render_template('register.html', error="Username is already taken")
            # Generate QR code for TOTP setup
            totp_uri = pyotp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name='My Blog')
            img = qrcode.make(totp_uri)
            buffered = BytesIO()
            img.save(buffered, format="PNG")
            totp_qr_code = "data:image/png;base64," + base64.b64encode(buffered.getvalue()).decode('utf-8')
            return render_template("register.html", totp_qr_code=totp_qr_code, show_totp_input=True, username=username)

        # Handle TOTP verification and log the user in
        elif 'totp_code' in request.form and 'username' in request.form:
            username = request.form['username']
            totp_code = request.form['totp_code']
            user = query_db("SELECT * FROM users WHERE username = ?", [username], one=True)
            if user:
                encrypted_totp_secret_b64 = user['totp_secret']
                encrypted_totp_secret = base64.b64decode(encrypted_totp_secret_b64)
                totp_secret = cipher_suite.decrypt(encrypted_totp_secret).decode()
                totp = pyotp.TOTP(totp_secret)
                if totp.verify(totp_code):
                    session['user_id'] = user['id']  # Log the user in
                    return redirect(url_for("index"))
                else:
                    flash("Invalid TOTP code. Please try again.", "error")
                    return render_template("register.html", show_totp_input=True,
                                           totp_qr_code=request.form["totp_qr_code"], username=username)
    return render_template("register.html")


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('user_email', None)
    session.clear()
    return redirect(url_for('index'))


@app.route("/google_auth")
def google_auth():
    # Generates a signed token for state because locally secure connection did not work with OAuth2.0
    state_data = {
        'timestamp': datetime.datetime.utcnow().isoformat()
    }
    state = serializer.dumps(state_data)
    google_auth_url = (
        f"{GOOGLE_AUTH_URL}?response_type=code"
        f"&client_id={CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        f"&scope=email profile"
        f"&state={state}"
        f"&access_type=offline"
        f"&prompt=select_account"
    )
    return redirect(google_auth_url)


@app.route("/google_callback")
def google_callback():
    try:
        state = request.args.get('state')
        if not state:
            flash("State-parameter missing.", "error")
            return redirect(url_for("login"))
        try:
            state_data = serializer.loads(state, max_age=300)  # Gyldig i 5 minutter
        except BadSignature:
            flash("Invalid state-parameter.", "error")
            return redirect(url_for("login"))
        except BadData:
            flash("Error in handling state-parameter.", "error")
            return redirect(url_for("login"))
        # Switch code for access token
        token_data = {
            "code": request.args.get("code"),
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "redirect_uri": REDIRECT_URI,
            "grant_type": "authorization_code",
        }
        token_response = requests.post(GOOGLE_TOKEN_URL, data=token_data)
        token_response.raise_for_status()
        # Get user information
        token_json = token_response.json()
        access_token = token_json.get("access_token")
        user_info_response = requests.get(
            GOOGLE_USER_INFO_URL,
            headers={"Authorization": f"Bearer {access_token}"}
        )
        user_info_response.raise_for_status()
        user_info = user_info_response.json()
        user_email = user_info.get("email")
        if not user_email:
            flash("Could not fetch email address.", "error")
            return redirect(url_for("login"))
        # Check if user in database
        user = find_user_by_email(user_email)
        if not user:
            add_google_user(user_email)
            user = find_user_by_email(user_email)
        # Log in user
        session["user_email"] = user_email
        session["user_id"] = user["id"]
        session.permanent = True
        return redirect(url_for("index"))
    except requests.RequestException as e:
        flash("Error during Google-authentication.", "error")
        return redirect(url_for("login"))


# Helper functions and database access methods

# Execute SQL query on database and retrieve result
def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


# Retrieve the logged-in user's information based on session data
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


# Inject user data into templates for use in navigation or display
@app.context_processor
def inject_user():
    return dict(user=get_user())


# Query database to find user by email address
def find_user_by_email(user_email):
    return query_db('SELECT * FROM users WHERE username = ?', [user_email], one=True)


# Add Google user to database, associating with OAuth provider
def add_google_user(user_email, oauth_provider="google", oauth_user_id=None):
    db = get_db()
    db.execute(
        'INSERT INTO users (username, password, totp_secret, oauth_provider, oauth_user_id) VALUES (?, ?, ?, ?, ?)',
        [user_email, "", "", oauth_provider, oauth_user_id]
    )
    db.commit()


# Validate password strength to ensure adequate security
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
    # Check if the user is logged in
    if "user_id" not in session:
        return redirect(url_for("login"))
    db = get_db()
    cursor = db.cursor()
    if request.method == "POST":
        comment = sanitize_input(request.form["comment"])
        sanitized_comment = bleach.linkify(comment)
        user_id = session.get("user_id")
        # Insert the comment along with the user_id into the database
        cursor.execute(
            "INSERT INTO comments (content, user_id) VALUES (?, ?)",
            (sanitized_comment, user_id)
        )
        db.commit()
    # Fetch comments along with usernames to display on the page
    cursor.execute("""
        SELECT comments.content, users.username
        FROM comments
        JOIN users ON comments.user_id = users.id
        ORDER BY comments.created_at DESC
    """)
    comments = cursor.fetchall()  # Fetch all rows from the query result
    return render_template("index.html", comments=comments)


@app.route("/om_meg")
def om_meg():
    return render_template("om_meg.html")


@app.route('/kontakt', methods=['GET', 'POST'])
def kontakt():
    if request.method == 'POST':
        message = sanitize_input(request.form.get('message', ''))
        return "Thank you for your message!"
    return render_template('kontakt.html')


# Custom error handler for rate-limiting, displays an error on excessive login attempts
@app.errorhandler(429)
def ratelimit_handler(exception):
    error_message = "Too many login attempts. Please try again in a minute."
    return render_template("login.html", error=error_message), 429


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host='0.0.0.0')
