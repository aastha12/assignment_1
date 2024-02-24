import uuid
from flask import Flask, request, jsonify, make_response
import hashlib
import logging
from flask_sqlalchemy import SQLAlchemy
import datetime
import os
import random

# Initialize logger
logging.basicConfig(filename='app.log', level=logging.INFO)

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# This is the base value, session lifetime will be randomized for each user session
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=15)
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    session_token = db.Column(db.String(50))
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_at = db.Column(db.DateTime, default=None)
    session_expiration = db.Column(db.DateTime)  # Stores the actual expiration time for each session

def admin_user():
    with app.app_context():
        db.create_all()
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_password = hashlib.sha256('admin'.encode()).hexdigest()
            admin_user = User(username='admin', password=admin_password, role='admin')
            db.session.add(admin_user)
            db.session.commit()
            app.logger.info("Created Admin user")

@app.route('/register', methods=['POST'])
def register_user():
    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        app.logger.info("Username or password not provided")
        return make_response(jsonify({'message': "Both username and password must be provided"}), 400)

    user = User.query.filter_by(username=username).first()
    if user:
        app.logger.info(f"Username {username} already exists")
        return make_response(jsonify({'message': "Username already exists!"}), 400)

    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    new_user = User(username=username, password=hashed_password, role='user')
    db.session.add(new_user)
    db.session.commit()

    app.logger.info(f"Username {username} registered")
    return make_response('', 201)

@app.route('/login', methods=['POST'])
def login_user():
    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        app.logger.info("Username or password not provided")
        return make_response(jsonify({'message': "Both username and password must be provided"}), 400)

    user = User.query.filter_by(username=username).first()

    if user:
        if user.failed_login_attempts >= 3 and user.locked_at is not None:
            if user.locked_at + datetime.timedelta(seconds=45) > datetime.datetime.now():
                return make_response(jsonify({'message': "Account locked. Try again later."}), 403)
            else:
                user.failed_login_attempts = 0

        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        if hashed_password == user.password:
            session_token = str(uuid.uuid4())
            user.session_token = session_token
            
            # Randomize session expiration time
            random_minutes = random.randint(5, 15)  # Randomize between 5 and 15 minutes
            user.session_expiration = datetime.datetime.now() + datetime.timedelta(minutes=random_minutes)
            
            db.session.commit()
            response = make_response('', 201)
            response.set_cookie('session_token', session_token, secure=True, httponly=True, samesite='Lax')
            app.logger.info(f"User {username} logged in with a session expiration of {random_minutes} minutes.")
            return response
        else:
            user.failed_login_attempts += 1
            user.locked_at = datetime.datetime.now()
            db.session.commit()
            return make_response(jsonify({'message': 'Invalid credentials'}), 401)
    else:
        return make_response(jsonify({'message': 'User not found'}), 401)

@app.route('/user', methods=['GET'])
def get_user_info():
    session_token = request.cookies.get('session_token')

    if not session_token:
        app.logger.info("Session token is missing")
        return make_response(jsonify({'message': 'Session token is required.'}), 401)

    user = User.query.filter_by(session_token=session_token).first()

    if user and user.session_expiration > datetime.datetime.now():
        app.logger.info(f"Accessed user info for {user.username}")
        return make_response(jsonify({'username': user.username, 'role': user.role}), 200)
    else:
        app.logger.info("Invalid session token or session expired")
        return make_response(jsonify({'message': 'Invalid session token or session expired.'}), 401)

@app.route('/admin', methods=['GET'])
def get_admin_info():
    session_token = request.cookies.get('session_token')

    if not session_token:
        app.logger.info("Session token is missing")
        return make_response(jsonify({'message': 'Session token is required.'}), 401)

    admin_user = User.query.filter_by(session_token=session_token, role='admin').first()

    if admin_user and admin_user.session_expiration > datetime.datetime.now():
        app.logger.info(f"Accessed admin info for {admin_user.username}")
        return make_response(jsonify({'username': admin_user.username, 'role': admin_user.role}), 200)
    else:
        app.logger.info("Invalid session token or not an admin")
        return make_response(jsonify({'message': 'Invalid session token or not authorized as admin.'}), 403)

@app.route('/changepw', methods=['POST'])
def change_password():
    username = request.json.get('username')
    old_password = request.json.get('old_password')
    new_password = request.json.get('new_password')

    if not username or not old_password or not new_password:
        app.logger.info("Required information not provided")
        return make_response(jsonify({'message': "Username, old password, and new password must be provided"}), 400)    

    if old_password == new_password:
        app.logger.info("Old and new passwords cannot be the same")
        return make_response(jsonify({'message': "New password must be different from old password"}), 400) 
        
    hashed_old_password = hashlib.sha256(old_password.encode()).hexdigest()
    user = User.query.filter_by(username=username).first()

    if user and user.password == hashed_old_password:
        hashed_new_password = hashlib.sha256(new_password.encode()).hexdigest()
        user.password = hashed_new_password
        user.session_token = str(uuid.uuid4())  # Generate new session token
        random_minutes = random.randint(5, 15)  # Randomize between 10 and 30 minutes for new session expiration
        user.session_expiration = datetime.datetime.now() + datetime.timedelta(minutes=random_minutes)  # Reset session expiration
        db.session.commit()
        app.logger.info(f"Password changed for user {username} with new session expiration of {random_minutes} minutes.")
        return make_response(jsonify({'message': 'Password changed successfully.'}), 200)
    else:
        app.logger.info("Invalid credentials for password change")
        return make_response(jsonify({'message': 'Invalid credentials.'}), 401)    

if __name__ == '__main__':
    admin_user()
    app.run(debug=True)