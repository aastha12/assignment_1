import uuid
from flask import Flask, request, jsonify, make_response
import hashlib
import logging
from flask_sqlalchemy import SQLAlchemy
import datetime
import os 
import bcrypt
#initalize logger
logging.basicConfig(filename='app.log', level=logging.INFO)

app = Flask(__name__)
app.secret_key =  os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
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


@app.route('/register',methods=['POST'])
def register_user():
    username = request.json.get('username')
    password = request.json.get('password').encode('utf-8')

    if not username or not password:
        app.logger.info("Username or password not provided")
        return make_response(jsonify({'message':"Both username and password must be provided"}),400)

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
    return make_response('',201)

#TODO: add db lock
@app.route('/login',methods=['POST'])
def login_user():
    username = request.json.get('username')
    password = request.json.get('password').encode('utf-8')

    if not username or not password:
        app.logger.info("Username or password not provided")
        return make_response(jsonify({'message':"Both username and password must be provided"}),400)

    #hashed_password = hashlib.sha256(password.encode()).hexdigest()
    # user = User.query.filter_by(username=username, password=hashed_password).first()
    user = User.query.filter_by(username=username).first()

    if user:
        # Check if the account is locked
        if user.failed_login_attempts >= 3:
            # Check if 45 seconmds has passed since the account was locked
            if user.locked_at + datetime.timedelta(seconds=45) < datetime.datetime.now():
                user.failed_login_attempts = 0  # reset
                db.session.commit()
            else:
                return make_response(jsonify({'message': "Account locked. Try again later."}), 403)
        
        user_password = user.password.encode('utf-8')
        if bcrypt.checkpw(password,user_password):     
            session_token = str(uuid.uuid4())
            user.session_token = session_token
            db.session.commit() 
            response = make_response('',201)
            response.set_cookie('session_token',session_token,secure=True, httponly=True, samesite='Lax')
            app.logger.info(f"Username {username} logged in")
            return response
        else:
            user.failed_login_attempts += 1
            user.locked_at = datetime.datetime.now()
            db.session.commit()
            app.logger.info(f"Invalid credentials during login")
            return make_response(jsonify({'message': 'Invalid credentials. Check username and password again.'}), 401)

            
    else:
        app.logger.info(f"User not found")
        return make_response(jsonify({'message':'User not found. Check username and password again.'}),401)

@app.route('/user', methods=['GET'])
def get_user_info():
    session_token = request.cookies.get('session_token')

    if not session_token:
        app.logger.info(f"Session toke is missing")
        return make_response(jsonify({'message': 'Session token is required.'}), 401)

    user = User.query.filter_by(session_token=session_token).first()

    if user:
        app.logger.info(f"Username {user.username} logged in")
        return make_response(jsonify({'message': f'Logged in as user {user.username}'}), 200)
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
        return make_response(jsonify({'message': f'Logged in as admin {admin_user.username}'}), 200)
    else:
        app.logger.info(f"Recheck credentials or session token")
        return make_response(jsonify({'message': 'Access denied. Admin privileges required.'}), 403)


@app.route('/changepw',methods=['POST'])
def change_password():
    username = request.json.get('username')
    old_password = request.json.get('old_password').encode('utf-8')
    new_password = request.json.get('new_password').encode('utf-8')

    if not username or not old_password or not new_password:
        app.logger.info("Username or password not provided")
        return make_response(jsonify({'message':"Username,old and new passwords must be provided"}),400)    

    if old_password==new_password:
        app.logger.info("new and old passwords are same")
        return make_response(jsonify({'message':"New password must be different from old password"}),400) 
        
    # hashed_old_password = hashlib.sha256(old_password.encode()).hexdigest()
    user = User.query.filter_by(username=username).first()

    if user and bcrypt.checkpw(old_password, user.password.encode('utf-8')):
        hashed_new_password = bcrypt.hashpw(new_password, bcrypt.gensalt())
        user.password = hashed_new_password.decode('utf-8')
        session_token = str(uuid.uuid4())
        user.session_token = session_token
        db.session.commit()
        response = make_response('', 201)
        response.set_cookie('session_token', session_token, secure=True, httponly=True, samesite='Lax')
        app.logger.info(f"Username {username} changed their password")
        return response
    else:
        app.logger.info("Invalid credentials")
        return make_response(jsonify({'message': 'Invalid credentials. Check username and password again.'}), 401)   

if __name__ == '__main__':
    admin_user()
    app.run(debug=True)