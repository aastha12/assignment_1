import uuid
from flask import Flask, request, jsonify, make_response
import hashlib
import logging
from flask_sqlalchemy import SQLAlchemy
import datetime
import os 
import bcrypt
import random
import re

#initalize logger
logging.basicConfig(filename='app.log', level=logging.INFO)

app = Flask(__name__)
app.secret_key =  os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=7)
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
        # Check if admin user exists
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            # Create admin user
            admin_password = 'admin'.encode('utf-8')
            hashed_password = bcrypt.hashpw(admin_password, bcrypt.gensalt())
            admin_user = User(username='admin', password=hashed_password.decode('utf-8'), role='admin')
            db.session.add(admin_user)
            db.session.commit()
            app.logger.info("Created Admin user")

def is_password_secure(password):
    #minimumm length
    if len(password) < 12:
        return False

    #uppercase letter
    if not re.search(r'[A-Z]', password):
        return False

    #lowercase letter
    if not re.search(r'[a-z]', password):
        return False

    #digit
    if not re.search(r'\d', password):
        return False

    #special character
    if not re.search(r'[!@#$%^&*()\-_=+{};:,<.>]', password):
        return False

    return True

@app.route('/register',methods=['POST'])
def register_user():
    username = request.json.get('username')
    password = request.json.get('password').encode('utf-8')

    if not username or not password:
        app.logger.info("Username or password not provided")
        return make_response(jsonify({'message':"Both username and password must be provided"}),400)

    if not is_password_secure(password.decode('utf-8')):
        app.logger.info("Password does not meet security requirements")
        return make_response(jsonify({'message':"Password must be at least 12 characters and include at least one uppercase letter, one lowercase letter, one digit, and one special character."}),400)

    #check if user already exists
    user = User.query.filter_by(username=username).first()
    if user:
        app.logger.info(f"Username {username} already exists")
        return make_response(jsonify({'message':"Username already exists!"}),400)

    hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
    new_user = User(username=username, password=hashed_password.decode('utf-8'), role='user')
    db.session.add(new_user)
    db.session.commit()

    app.logger.info(f"Username {username} registered")
    return make_response(jsonify({'message':"Registration completed"}),201)


@app.route('/login',methods=['POST'])
def login_user():
    username = request.json.get('username')
    password = request.json.get('password').encode('utf-8')

    if not username or not password:
        app.logger.info("Username or password not provided")
        return make_response(jsonify({'message':"Both username and password must be provided"}),400)


    user = User.query.filter_by(username=username).first()

    if user:
        # Check if the account is locked
        if user.failed_login_attempts >= 3:
            # Check if 45 seconmds has passed since the account was locked
            if user.locked_at + datetime.timedelta(seconds=45) < datetime.datetime.now():
                app.logger.warning(f"Account locked due to failed login attempts, user: {username}")
                user.failed_login_attempts = 0  # reset
                db.session.commit()
            else:
                return make_response(jsonify({'message': "Account locked. Try again later."}), 403)
        
        user_password = user.password.encode('utf-8')
        if bcrypt.checkpw(password,user_password):     
            session_token = str(uuid.uuid4())
            user.session_token = session_token

            # Randomize session expiration time
            random_minutes = random.randint(3, 7)  # Randomize between 5 and 15 minutes
            user.session_expiration = datetime.datetime.now() + datetime.timedelta(minutes=random_minutes)
            
            db.session.commit() 
            response = make_response('',201)
            response.set_cookie('session_token',session_token,secure=True, httponly=True, samesite='Lax')
            app.logger.info(f"Username {username} logged in with a session expiration of {random_minutes} minutes.")
            return response
        else:
            user.failed_login_attempts += 1
            user.locked_at = datetime.datetime.now()
            db.session.commit()
            app.logger.warning(f"Failed login attempt for user: {username}")
            return make_response(jsonify({'message': 'Invalid credentials. Check username and password again.'}), 401)

            
    else:
        app.logger.warning(f"Login attempt for non-existing user: {username}")
        return make_response(jsonify({'message':'User not found. Check username and password again.'}),401)

@app.route('/user', methods=['GET'])
def get_user_info():
    session_token = request.cookies.get('session_token')

    if not session_token:
        app.logger.info(f"Session toke is missing")
        return make_response(jsonify({'message': 'Session token is required.'}), 401)

    user = User.query.filter_by(session_token=session_token).first()
    role = user.role
    if user and role != 'admin':
        app.logger.info(f"Username {user.username} logged in")
        return make_response(jsonify({'message': f'Logged in as user {user.username}'}), 200)
    elif user and role == 'admin':
        app.logger.warning(f"Trying to login as user with admin token")
        return make_response(jsonify({'message': f'Invalid session token'}), 200)
    else:
        app.logger.info(f"Check the credentials or session token again")
        return make_response(jsonify({'message': 'Invalid credentials or session expired.'}), 401)              

@app.route('/admin', methods=['GET'])
def get_admin_info():
    session_token = request.cookies.get('session_token')

    if not session_token:
        app.logger.info(f"Session toke is missing")
        return make_response(jsonify({'message': 'Session token is required.'}), 401)

    # Check if the user with the provided session token is an admin
    admin_user = User.query.filter_by(session_token=session_token, role='admin').first()

    if admin_user:
        app.logger.info(f"Username {admin_user.username} logged in as admin")
        return make_response(jsonify({'message': f'Username: {admin_user.username} logged in as Admin'}), 200)
    else:
        app.logger.info(f"Recheck credentials or session token")
        return make_response(jsonify({'message': 'Access denied. Admin privileges required.'}), 403)


@app.route('/changepw',methods=['POST'])
def change_password():
    username = request.json.get('username')
    old_password = request.json.get('old_password').encode('utf-8')
    new_password = request.json.get('new_password').encode('utf-8')

    if not username or not old_password or not new_password:
        app.logger.info("Username or password not provided for password change")
        return make_response(jsonify({'message':"Username,old and new passwords must be provided"}),400)    

    if old_password==new_password:
        app.logger.info("new and old passwords are same")
        return make_response(jsonify({'message':"New password must be different from old password"}),400) 
        
    # hashed_old_password = hashlib.sha256(old_password.encode()).hexdigest()
    user = User.query.filter_by(username=username).first()

    if user and bcrypt.checkpw(old_password, user.password.encode('utf-8')):

        if not is_password_secure(new_password.decode('utf-8')):
            app.logger.warning(f"New password does not meet security requirements for user {username}")
            return make_response(jsonify({'message':"Password must be at least 12 characters and include at least one uppercase letter, one lowercase letter, one digit, and one special character."}),400)        

        hashed_new_password = bcrypt.hashpw(new_password, bcrypt.gensalt())
        user.password = hashed_new_password.decode('utf-8')
        session_token = str(uuid.uuid4())
        user.session_token = session_token
        random_minutes = random.randint(5, 15)  # Randomize between 5 and 15 minutes for new session expiration
        user.session_expiration = datetime.datetime.now() + datetime.timedelta(minutes=random_minutes)  # Reset session expiration
        db.session.commit()
        response = make_response('', 201)
        response.set_cookie('session_token', session_token, secure=True, httponly=True, samesite='Lax')
        app.logger.info(f"Username {username} changed their password with a session expiration of {random_minutes} minutes.")
        return response
    else:
        app.logger.warning(f"Failed password change attempt for user: {username}")
        return make_response(jsonify({'message': 'Invalid credentials. Check username and password again.'}), 401)   

if __name__ == '__main__':
    admin_user()
    app.run(debug=True)