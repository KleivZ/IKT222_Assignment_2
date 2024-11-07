from app import app, init_db

if __name__ == "__main__":
    init_db()  # Initialiser databasen
    app.run(debug=True, host='0.0.0.0')