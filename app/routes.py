from flask import render_template, request, redirect, url_for, session
import bleach

from . import app, get_db  # Importer app fra __init__.py
from .utils import query_db  # Importer query_db fra utils.py

# --- Ruter for bloggen ---
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

    # Hent blogginnlegg fra databasen
    cursor.execute("SELECT * FROM blog_posts ORDER BY created_at DESC")
    blog_posts = cursor.fetchall()

    return render_template("index.html", comments=comments, blog_posts=blog_posts)

@app.route("/om_meg")
def om_meg():
    return render_template("om_meg.html")

@app.route('/kontakt', methods=['GET', 'POST'])
def kontakt():
    if request.method == 'POST':
        # Her kan du legge til kode for å håndtere innsending av kontaktskjemaet.
        # For eksempel, lagre dataene i en database eller sende en e-post.
        return "Takk for meldingen din!"
    else:
        return render_template('kontakt.html')