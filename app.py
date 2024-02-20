import sqlite3
import uuid
from flask import Flask, request, jsonify, make_response
import hashlib
import logging
from flask_sqlalchemy import SQLAlchemy
import datetime

#initalize logger
logging.basicConfig(filename='app.log', level=logging.INFO)

app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=15)
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    session_token = db.Column(db.String(50))


def admin_user():
    with app.app_context():
        db.create_all()
        # Check if admin user exists
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            # Create admin user
            admin_password = hashlib.sha256('admin'.encode()).hexdigest()
            admin_user = User(username='admin', password=admin_password, role='admin')
            db.session.add(admin_user)
            db.session.commit()
            app.logger.info("Created Admin user")


@app.route('/register',methods=['POST'])
def register_user():
    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        app.logger.info("Username or password not provided")
        return make_response(jsonify({'message':"Both username and password must be provided"}),400)

    #check if user already exists
    user = User.query.filter_by(username=username).first()
    if user:
        app.logger.info(f"Username {username} already exists")
        return make_response(jsonify({'message':"Username already exists!"}),400)

    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    new_user = User(username=username, password=hashed_password, role='user')
    db.session.add(new_user)
    db.session.commit()

    app.logger.info("Username {username} registered")
    return make_response('',201)


@app.route('/login',methods=['POST'])
def login_user():
    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        app.logger.info("Username or password not provided")
        return make_response(jsonify({'message':"Both username and password must be provided"}),400)

    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    user = User.query.filter_by(username=username, password=hashed_password).first()

    if user:
        session_token = str(uuid.uuid4())
        user.session_token = session_token
        db.session.commit()
        response = make_response('',201)
        response.set_cookie('session_token',session_token)
        app.logger.info("Username {username} logged in")
        return response
    else:
        app.logger.info(f"Invalid credentials during login")
        return make_response(jsonify({'message':'Invalid credentials. Check username and password again.'}),401)

@app.route('/changepw',methods=['POST'])
def change_password():
    username = request.json.get('username')
    old_password = request.json.get('old_password')
    new_password = request.json.get('new_password')

    if not username or not old_password or not new_password:
        app.logger.info("Username or password not provided")
        return make_response(jsonify({'message':"Username,old and new passwords must be provided"}),400)    

    if old_password==new_password:
        app.logger.info("new and old passwords are same")
        return make_response(jsonify({'message':"New password must be different from old password"}),400) 
        
    hashed_old_password = hashlib.sha256(old_password.encode()).hexdigest()
    user = User.query.filter_by(username=username, password=hashed_old_password).first()

    if user:
        user.password = hashlib.sha256(new_password.encode()).hexdigest()
        session_token = str(uuid.uuid4())
        user.session_token = session_token
        db.session.commit()
        response = make_response('',201)
        response.set_cookie('session_token',session_token)
        app.logger.info("Username {username} changed their password")
        return response
    else:
        app.logger.info(f"Invalid credentials")
        return make_response(jsonify({'message':'Invalid credentials. Check username and password again.'}),401)    

if __name__ == '__main__':
    admin_user()
    app.run(debug=True)