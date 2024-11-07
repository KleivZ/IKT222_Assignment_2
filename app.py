import base64
import os
import sqlite3
import requests
from flask import Flask, render_template, request, g, redirect, session, url_for
import bcrypt
import pyotp
import qrcode
from io import BytesIO
import bleach
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from google_auth_oauthlib.flow import Flow

app = Flask(__name__)
app.secret_key = os.urandom(24)  # For session handling

CLIENT_ID = "1057743644961-ln1m6f365m8cbqpce3v08oomgepoc4la.apps.googleusercontent.com"
CLIENT_SECRET = "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"
REDIRECT_URI = "http://localhost:5000/google_callback"
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USER_INFO_URL = "https://www.googleapis.com/oauth2/v1/userinfo"

AUTH_CODES = {}  # Temporary storage for auth codes. Use a proper database in a real-world scenario.
TOKENS = {}      # Temporary storage for access tokens.

# Initialize Flask-Limiter with default limit key (client's IP address)
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],  # Default rate limits for all routes
    app=app
)

flow = Flow.from_client_secrets_file(
    'client_secret.json',
    scopes=['openid', 'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/userinfo.profile'],
    redirect_uri=REDIRECT_URI
)

# Cookie settings to prevent cookie theft
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True


# Content Security Policy function
@app.after_request
def apply_csp(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' "
        "https://code.jquery.com "
        "https://cdn.jsdelivr.net "
        "https://stackpath.bootstrapcdn.com; "
        "style-src 'self' "
        "https://stackpath.bootstrapcdn.com; "
        "img-src 'self' data:; "  # Allow data URLs for QR codes
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'self'"
    )
    return response


DATABASE = 'database.db'


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # Enable column access by name
    return db


@app.teardown_appcontext
def close_connection(exception=None):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


@app.route("/", methods=["GET", "POST"])
def index():
    db = get_db()
    cursor = db.cursor()

    if request.method == "POST":
        comment = request.form["comment"]

        # Output validation using the Bleach library
        sanitized_comment = bleach.linkify(bleach.clean(comment))

        # Insert the sanitized comment into the comments table
        cursor.execute(
            "INSERT INTO comments (content) VALUES (?)",
            (sanitized_comment,)
        )
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
    else:
        return render_template('kontakt.html')


def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()


# Apply rate limit to login route to prevent brute-force attacks
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("3 per minute")  # Allow a maximum of 3 login attempts per minute
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


# Apply rate limit to registration route
@app.route("/register", methods=["GET", "POST"])
@limiter.limit("3 per minute")  # Limit registration attempts to 3 per minute
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if password != confirm_password:
            error = 'Passordene matcher ikke'
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
        except Exception as e:
            error = 'Noe gikk galt under registreringen'
            print(f"Database error: {e}")
            return render_template('register.html', error=error)
    return render_template('register.html')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))


@app.route('/verify_2fa/<username>', methods=['GET', 'POST'])
@limiter.limit("3 per minute")  # Limit verification attempts to prevent brute-force on 2FA codes
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


@app.errorhandler(429)
def ratelimit_handler():
    return render_template("login.html", error="Too many login attempts. Please try again in a minute."), 429


@app.route('/auth')
def auth():
    return redirect(url_for('index'))


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
    """Handles Google's callback and exchanges the authorization code for an access token."""
    code = request.args.get("code")
    if not code:
        return "Authorization failed.", 400

    # Exchange authorization code for access token
    token_data = {
        "code": code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code",
    }
    token_response = requests.post(GOOGLE_TOKEN_URL, data=token_data)
    token_json = token_response.json()
    access_token = token_json.get("access_token")
    if not access_token:
        return "Failed to retrieve access token.", 400

    # Use the access token to fetch the user’s profile information, including email
    user_info_response = requests.get(
        "https://www.googleapis.com/oauth2/v2/userinfo",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    user_info = user_info_response.json()

    # Extract the email and use it as the username
    user_email = user_info.get("email")
    if not user_email:
        return "Failed to retrieve email.", 400

    # Check and create the user if needed
    user = find_user_by_email(user_email)
    if not user:
        add_google_user(user_email)

    # Store user in session
    session["user_email"] = user_email
    return redirect(url_for("index"))


def add_google_user(user_email, oauth_provider="google", oauth_user_id=None):
    db = get_db()
    # Insert the user with a placeholder password and OAuth details
    db.execute(
        'INSERT INTO users (username, password, oauth_provider, oauth_user_id) VALUES (?, ?, ?, ?)',
        [user_email, "", oauth_provider, oauth_user_id]
    )
    db.commit()


@app.route('/callback')
def callback():
    return redirect(url_for('index'))


# Helper functions
def get_user():
    user_id = session.get('user_id')
    if user_id:
        return query_db('SELECT * FROM users WHERE id = ?', [user_id], one=True)
    return None


@app.context_processor
def inject_user():
    return dict(user=get_user())


def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


def find_user_by_email(user_email):
    user = query_db('SELECT * FROM users WHERE username = ?', [user_email], one=True)
    return user


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host='0.0.0.0')
