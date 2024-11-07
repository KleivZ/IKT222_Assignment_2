import os
import sqlite3
from flask import Flask, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from PIL import Image

app = Flask(__name__)  # Definer app her
app.secret_key = os.urandom(24)

# Initialize Flask-Limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    app=app,
    storage_uri="memory://"  # Use memory storage for now
)

# Database configuration
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

# Importer ruter og andre funksjoner etter at applikasjonen er opprettet
from . import routes, auth  # Importer routes.py og auth.py