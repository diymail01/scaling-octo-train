import sqlite3
import hashlib
import os
from typing import Optional, Dict

# Initialize database
def init_db():
    """Initialize the SQLite database with users table if it doesn't exist"""
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Create users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create default admin user if none exists
    c.execute('SELECT COUNT(*) FROM users')
    if c.fetchone()[0] == 0:
        # Default admin user: admin/admin123
        password_hash = hashlib.sha256('admin123'.encode()).hexdigest()
        c.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                 ('admin', password_hash, 'scanner'))
    
    conn.commit()
    conn.close()

def hash_password(password: str) -> str:
    """Hash a password for storing"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_user(username: str, password: str) -> Optional[Dict]:
    """Verify user credentials"""
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()
    
    if user and user['password_hash'] == hash_password(password):
        return dict(user)
    return None

def list_users():
    """List all users"""
    try:
        conn = sqlite3.connect('users.db')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('SELECT username, role FROM users ORDER BY username')
        users = [dict(row) for row in c.fetchall()]
        return users
    except Exception as e:
        print(f"Error listing users: {e}")
        return []
    finally:
        conn.close()

def create_user(username: str, password: str, role: str) -> bool:
    """Create a new user"""
    if role not in ['scanner', 'viewer']:
        return False
        
    try:
        password_hash = hash_password(password)
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                 (username, password_hash, role))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

# Initialize database when this module is imported
init_db()
