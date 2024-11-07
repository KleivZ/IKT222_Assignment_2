from . import get_db  # Importer get_db fra __init__.py

def query_db(query, args=(), one=False):
    """
    Hjelpefunksjon for å kjøre database-spørringer.
    """
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def validate_password(password):
    """
    Validerer passordstyrke.
    Sjekker om passordet er minst 8 tegn langt og inneholder minst ett tall og ett spesialtegn.
    """
    if len(password) < 8:
        return False
    if not any(char.isdigit() for char in password):
        return False
    if not any(not char.isalnum() for char in password):
        return False
    return True

def sanitize_input(input_string):
    """
    Sanitiserer brukerinput for å forhindre XSS-angrep.
    """
    return bleach.clean(input_string, tags=[], attributes={}, styles=[], strip=True)