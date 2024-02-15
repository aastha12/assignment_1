import sqlite3
import uuid
from flask import Flask, request, jsonify, make_response
import hashlib
import logging
# from flask_talisman import Talisman

app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

#initalize logger
logging.basicConfig(filename='app.log', level=logging.INFO)

#initlize talisman with default settings
# talisman = Talisman(app)

#initializa db and create connection
conn = sqlite3.connect("app.db",timeout=20)
cursor = conn.cursor()

#create users table
cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY,username TEXT UNIQUE,password TEXT, role TEXT)")

#create admin user role if it doesn't exist
result = cursor.execute("SELECT COUNT(*) FROM users WHERE role='admin' ")
if result==0:
    #encrypt the password 'admin'
    admin_password = hashlib.sha256('admin'.encode()).hexdigest()
    cursor.execute("INSERT INTO users (username,password,role) VALUES (?,?,?)",('admin',admin_password,'admin'))

#close connection
conn.commit()
conn.close()

@app.route('/register',methods=['POST'])
def register_user():
    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        return make_response(jsonify({'message':"Both username and password must be provided"}),400)
    
    with sqlite3.connect("app.db",timeout=20) as conn:
        cursor = conn.cursor()

        result = cursor.execute("SELECT COUNT(*) FROM users WHERE username= (?)",(username,))
        result = cursor.fetchone()[0] 
        if result>0:
            return make_response(jsonify({'message':"Username already exists!"}),400)

        password = hashlib.sha256(password.encode()).hexdigest()
        cursor.execute("INSERT INTO users (username,password,role) VALUES (?,?,?)",(username,password,'user'))
        conn.commit()

    return make_response('',201)

@app.route('/login',methods=['POST'])
def login_user():
    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        return make_response(jsonify({'message':"Both username and password must be provided"}),400)
    
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    password = hashlib.sha256(password.encode()).hexdigest()
    cursor.execute("SELECT * FROM users WHERE username=? and password=?",(username,password))
    result = cursor.fetchone()

    if result:
        session_token = str(uuid.uuid4())
        cursor.execute("UPDATE users SET session_token=? WHERE id=?",(session_token,result[0]))
        conn.commit()
        conn.close()
        response = make_response('',201)
        response.set_cookie('session_token',session_token)
        return response
    else:
        conn.commit()
        conn.close()
        return make_response(jsonify({'message':'Invalid credentials. Check username and password again.'}),401)

if __name__ == '__main__':
    app.run(debug=True)