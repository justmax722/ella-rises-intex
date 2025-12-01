-- Create users table for Ella Rises application
-- Run this script in pgAdmin

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    user_role VARCHAR(50) NOT NULL CHECK (user_role IN ('manager', 'user', 'donor')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create index on email for faster lookups
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- Create index on user_role for filtering
CREATE INDEX IF NOT EXISTS idx_users_role ON users(user_role);

-- Example of how to insert a test user (password should be hashed in production)
-- INSERT INTO users (email, password, user_role) 
-- VALUES ('test@example.com', 'hashed_password_here', 'user');

