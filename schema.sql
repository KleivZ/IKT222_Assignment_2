-- Users table to store user information
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password BLOB NOT NULL,                -- Stores hashed passwords
    totp_secret TEXT,                      -- Stores TOTP secret for 2FA
    remember_token TEXT,                   -- Remembers token for 2FA
    oauth_provider TEXT,                   -- Stores OAuth provider name
    oauth_user_id TEXT,                    -- Stores user ID from OAuth provider
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Comments table to store user comments with sanitization
CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Tokens table to store OAuth access tokens securely
CREATE TABLE IF NOT EXISTS tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    access_token TEXT NOT NULL,            -- Stores OAuth access token
    token_type TEXT NOT NULL,              -- Token type (e.g., Bearer)
    expires_at TIMESTAMP,                  -- Expiration timestamp for the access token
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Encrypted data table for sensitive information
CREATE TABLE IF NOT EXISTS encrypted_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    encrypted_content BLOB NOT NULL,       -- Stores encrypted data
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Table to store blog posts
CREATE TABLE IF NOT EXISTS blog_posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);