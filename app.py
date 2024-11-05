import os
import sqlite3
from flask import Flask, render_template, request, g, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import qrcode
from io import BytesIO
import bleach

app = Flask(__name__)
app.secret_key = os.urandom(24)  # For session handling

# Mock constants for client ID and secret.
CLIENT_ID = "YOUR_CLIENT_ID"
CLIENT_SECRET = "YOUR_CLIENT_SECRET"
REDIRECT_URI = "http://localhost:5000/callback"

AUTH_CODES = {}  # Temporary storage for auth codes. Use a proper database in a real-world scenario.
TOKENS = {}      # Temporary storage for access tokens.

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
    return db

@app.teardown_appcontext
def close_connection(exception):
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

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Process login form submission
        username = request.form["username"]
        password = request.form["password"]

        # Add logic to validate the user credentials
        user = query_db('SELECT * FROM users WHERE username = ?', [username], one=True)

        if user and check_password_hash(user['password'], password):
            # Logg inn brukeren (for eksempel ved å sette en sesjonsvariabel)
            session['user_id'] = user['id']
            return redirect('/')  # Redirect til hjemmesiden etter vellykket innlogging
        else:
            # Ugyldig brukernavn eller passord
            error = 'Ugyldig brukernavn eller passord'
            return render_template('login.html', error=error)
    return render_template('login.html')

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Logic for registering a new user
        username = request.form["username"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if password != confirm_password:
            error = 'Passordene matcher ikke'
            return render_template('register.html', error=error)

        # Hash passordet
        hashed_password = generate_password_hash(password)

        try:
            # Generer en TOTP-hemmelighet
            totp_secret = pyotp.random_base32()

            # Lag en URI for QR-koden
            totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name='Min Blogg')

            # Generer QR-koden
            img = qrcode.make(totp_uri)
            buffered = BytesIO()
            img.save(buffered, format="PNG")
            totp_qr_code = "data:image/png;base64," + buffered.getvalue().encode('base64').decode('utf-8')

            # Lagre brukeren i databasen
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

# --- 2FA ruter ---
@app.route('/verify_2fa/<username>', methods=['GET', 'POST'])
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
                return render_template('2fa.html', username=username, error=error)
    return render_template('2fa.html', username=username)

# --- OAuth2 ruter ---
@app.route('/auth')
def auth():
    return redirect(url_for('index'))

@app.route('/callback')
def callback():
    return redirect(url_for('index'))

# --- Hjelpefunksjoner ---
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

if __name__ == "__main__":
    init_db()
    app.run(debug=True, host='0.0.0.0')
