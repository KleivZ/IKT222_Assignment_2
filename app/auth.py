from flask import render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from . import app  # Importer app fra __init__.py
import pyotp
import qrcode
from io import BytesIO
import base64
from . import limiter  # Importer limiter fra __init__.py
from .utils import query_db  # Importer query_db fra utils.py
import sqlite3
from PIL import Image

# OAuth2-konfigurasjon
CLIENT_ID = "din_client_id"  # Erstatt med din faktiske klient-ID
CLIENT_SECRET = "din_client_secret"  # Erstatt med din faktiske klient-hemmelighet
REDIRECT_URI = "http://localhost:5000/google_callback"  # URL-en som Google vil omdirigere til etter autentisering
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)

# --- Autentiseringsruter ---
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")  # Rate limiting for login attempts
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = query_db('SELECT * FROM users WHERE username = ?', [username], one=True)

        if user and check_password_hash(user['password'], password):
            if user['totp_secret']:
                return redirect(url_for('verify_2fa', username=username))
            session['user_id'] = user['id']
            return redirect('/')
        else:
            error = 'Ugyldig brukernavn eller passord'
            return render_template('login.html', error=error)

    return render_template('login.html')

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("3 per minute")  # Rate limiting for registration attempts
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if password != confirm_password:
            error = 'Passordene matcher ikke'
            return render_template('register.html', error=error)

        # Sjekk om passordet oppfyller kravene
        if not validate_password(password):
            error = 'Passordet må være minst 8 tegn langt og inneholde minst ett tall og ett spesialtegn.'
            return render_template('register.html', error=error)

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
            totp_qr_code = "data:image/png;base64," + base64.b64encode(buffered.getvalue()).decode('utf-8')

            # Lagre brukeren i databasen
            get_db().execute('INSERT INTO users (username, password, totp_secret) VALUES (?, ?, ?)',
                             [username, hashed_password, totp_secret])
            get_db().commit()

            return render_template('register.html', totp_qr_code=totp_qr_code)
        except sqlite3.IntegrityError:
            error = 'Brukernavnet er allerede i bruk.'
            return render_template('register.html', error=error)
        except Exception as e:
            error = 'Noe gikk galt under registreringen'
            print(f"Database error: {e}")
            return render_template('register.html', error=error)

    return render_template('register.html')

# --- OAuth2 ruter ---
@app.route('/google_auth')
def google_auth():
    # Hent Google provider config
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # Bruk library til å lage en request til Google auth endpoint
    request_uri = oauth.google.authorize_access_token(
        redirect_uri=REDIRECT_URI
    )
    return redirect(request_uri)


# --- OAuth2 ruter ---
@app.route('/google_callback')
def google_callback():
    # Get authorization code Google sent back to you
    code = request.args.get("code")

    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]

    # Forbered og send en request til token endpoint
    token_url, headers, body = oauth.google.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(CLIENT_ID, CLIENT_SECRET),
    )

    # Sjekk statuskode før vi prøver å parse token
    if token_response.status_code != 200:
        error_message = f"Feil ved token-forespørselen: {token_response.status_code} {token_response.text}"
        return render_template('error.html', error=error_message)

    # Parse token
    oauth.google.parse_id_token(token_response, claims_options={'iss': {'essential': False}})
    
    # Forbered en request til Google people API
    google = oauth.create_client('google')
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = google.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)

    if userinfo_response.status_code == 200:
        user_info = userinfo_response.json()

        if user_info.get("email_verified"):
            unique_id = user_info["sub"]
            users_email = user_info["email"]
            picture = user_info["picture"]
            users_name = user_info["given_name"]
        else:
            return "User email not available or not verified by Google.", 400
    else:
        error_message = f"Feil ved henting av brukerinformasjon: {userinfo_response.status_code} {userinfo_response.text}"
        return render_template('error.html', error=error_message)

    # Lagre brukeren i databasen hvis de ikke finnes fra før
    user = query_db('SELECT * FROM users WHERE oauth_user_id = ?', [unique_id], one=True)
    if not user:
        try:
            get_db().execute('INSERT INTO users (oauth_provider, oauth_user_id, username) VALUES (?, ?, ?)',
                             ['google', unique_id, users_email])
            get_db().commit()
            user = query_db('SELECT * FROM users WHERE oauth_user_id = ?', [unique_id], one=True)
        except Exception as e:
            error = 'Noe gikk galt under registreringen'
            print(f"Database error: {e}")
            return render_template('index.html', error=error)

    # Logg inn brukeren
    session['user_id'] = user['id']
    return redirect(url_for('index'))

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
# (Disse rutene er antageligvis implementert av gruppemedlem 3)
# @app.route('/auth')
# def auth():
#     # ...

# @app.route('/callback')
# def callback():
#     # ...

# Hjelpefunksjon for å validere passord
def validate_password(password):
    if len(password) < 8:
        return False
    if not any(char.isdigit() for char in password):
        return False
    if not any(not char.isalnum() for char in password):
        return False
    return True