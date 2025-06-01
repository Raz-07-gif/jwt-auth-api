from flask import Flask, request, jsonify
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt
)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
import sqlite3

app = Flask(__name__)

# ---- JWT Config ----
app.config['JWT_SECRET_KEY'] = 'super-secret-key'  # Change this in production
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=15)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']

jwt = JWTManager(app)

# ---- In-Memory Blacklist Store ----
blacklist = set()

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    return jwt_payload['jti'] in blacklist


# ---- Create Users Table ----
def create_user_table():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

create_user_table()

# ---- Register Route ----
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    hashed_pw = generate_password_hash(password)

    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
        conn.commit()
        conn.close()
        return jsonify({"message": "User registered successfully"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 409

# ---- Login Route ----
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if user and check_password_hash(user[2], password):
        access_token = create_access_token(identity=str(user[0]))
        refresh_token = create_refresh_token(identity=str(user[0]))
        return jsonify(access_token=access_token, refresh_token=refresh_token)
    else:
        return jsonify({"error": "Invalid credentials"}), 401

# ---- Protected Profile Route ----
@app.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    user_id = get_jwt_identity()
    return jsonify(message=f"Welcome User {user_id}!")

# ---- Logout Route ----
@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()['jti']
    blacklist.add(jti)
    return jsonify({"message": "Successfully logged out"}), 200

# ---- Refresh Token Route ----
@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity)
    return jsonify(access_token=access_token)

# ---- Optional Home Route ----
@app.route('/')
def home():
    return '<h3>✅ JWT Auth API is Running. Use Postman to test /register, /login, /refresh, /logout, /profile</h3>'

# ---- Run Server ----
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
 
