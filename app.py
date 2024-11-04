import uuid

from flask import Flask, render_template, request, g, redirect, session
import os
import sqlite3
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
        "img-src 'self'; "
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
        session["username"] = username  # Mock login
        render_template('index.html')
    return render_template('login.html')


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Logic for registering a new user
        username = request.form["username"]
        password = request.form["password"]
        # Save the new user in the database, hash the password, etc.
        return render_template('login.html')
    return render_template('register.html')


@app.route("/auth", methods=["GET"])
def auth():
    """
    Endpoint where the client sends the user to request their authorization.
    After authorization, user is redirected back to the client with an auth code.
    """
    # 1. Extract 'client_id', 'redirect_uri', 'state', etc. from the request.
    client_id = request.args.get("client_id")
    redirect_uri = request.args.get("redirect_uri")
    state = request.args.get("state")

    # 2. Validate 'client_id' and 'redirect_uri' against registered client details.
    if client_id != CLIENT_ID or redirect_uri != REDIRECT_URI:
        return "Invalid client_id or redirect_uri", 400

    # 3. Display an authorization page to the user to grant permission.
    # Typically, this would involve rendering a template asking for user consent.
    # For simplicity, we'll assume consent is granted automatically here.
    # In a real application, you would ask for user confirmation.

    # 4. If user grants permission, generate an authorization code.
    import uuid
    auth_code = str(uuid.uuid4())

    # 5. Save the authorization code and associated data.
    AUTH_CODES[auth_code] = {"client_id": client_id, "redirect_uri": redirect_uri, "state": state}

    # 6. Redirect the user back to 'redirect_uri' with the 'code' and 'state'.
    return redirect(f"{redirect_uri}?code={auth_code}&state={state}")


@app.route("/token", methods=["POST"])
def token():
    """
    Endpoint where the client exchanges the authorization code for an access token.
    """
    # 1. Extract 'code', 'redirect_uri', 'client_id', 'client_secret' from the request.
    code = request.form.get("code")
    redirect_uri = request.form.get("redirect_uri")
    client_id = request.form.get("client_id")
    client_secret = request.form.get("client_secret")

    # 2. Verify that the 'code' is valid and has not expired.
    auth_data = AUTH_CODES.get(code)
    if not auth_data or auth_data["redirect_uri"] != redirect_uri:
        return {"error": "Invalid authorization code or redirect_uri"}, 400

    # 3. Validate 'client_id' and 'client_secret'.
    if client_id != CLIENT_ID or client_secret != CLIENT_SECRET:
        return {"error": "Invalid client credentials"}, 400

    # 4. Generate an access token (and optionally, a refresh token).
    access_token = str(uuid.uuid4())

    # 5. Save the access token for later validation.
    TOKENS[access_token] = {"client_id": client_id, "user_data": "User specific data"}

    # 6. Return the access token (and optionally, a refresh token) in a JSON response.
    return {"access_token": access_token, "token_type": "Bearer"}, 200


@app.route("/protected_resource", methods=["GET"])
def protected_resource():
    """
    A protected endpoint the client can access using the access token.
    """
    # 1. Extract the access token from the request's Authorization header.
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return {"error": "Unauthorized"}, 401

    access_token = auth_header.split(" ")[1]

    # 2. Validate the access token.
    token_data = TOKENS.get(access_token)
    if not token_data:
        return {"error": "Invalid or expired token"}, 401

    # 3. If valid, proceed to access the protected resource and return the data.
    # Here, we can return user-specific data or other sensitive information.
    return {"data": "Protected resource data"}, 200



if __name__ == "__main__":
    init_db()
    app.run(debug=False, host='0.0.0.0')
