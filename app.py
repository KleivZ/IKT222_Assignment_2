from flask import Flask, render_template, request, g
import sqlite3
import bleach

app = Flask(__name__)

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


if __name__ == "__main__":
    init_db()
    app.run(debug=False, host='0.0.0.0')
