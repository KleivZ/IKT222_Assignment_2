import os
from flask import Flask, render_template, request, g
import sqlite3

app = Flask(__name__)

# Liste for å lagre kommentarer
# (I en ekte applikasjon vil du vanligvis lagre kommentarene i en database)
comments = []  

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        comment = request.form["comment"]
        comments.append(comment)
    return render_template("index.html", comments=comments)

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

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')

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

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

# if __name__ == '__main__':
#     init_db()
#     app.run(debug=True)

