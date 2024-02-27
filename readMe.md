# Install virtual env:

`pipenv install`

# Activate it

`pipenv shell`

# How to test endpoint:

Run `python app.py` in a command line with the venv activated.

In another command line:

### Register endpoint:
`curl -i -X POST http://localhost:5000/register -H "Content-Type: application/json" -d "{\"username\": \"test\", \"password\": \"test\"}"` 

### Login and Get User endpoint:
`curl -i -X POST http://localhost:5000/login -H "Content-Type: application/json" -d "{\"username\": \"aastha2\", \"password\": \"user\"}"`

`curl -i -X GET http://localhost:5000/user -H "Content-Type: application/json" -b "session_token=<insert_token>;"`


### Login and Get Admin endpoint:
`curl -i -X POST http://localhost:5000/login -H "Content-Type: application/json" -d "{\"username\": \"admin\", \"password\": \"admin\"}"`

`curl -i -X GET http://localhost:5000/admin -H "Content-Type: application/json" -b "session_token=<insert_token>"`

### Change Password endpoint:
`curl -i -X POST http://localhost:5000/changepw -H "Content-Type: application/json" -d "{\"username\": \"aastha2\", \"old_password\": \"user2\",\"new_password\":\"user\"}"`

### Account Locked after incorrect password (3 retries):
```
curl -i -X POST http://localhost:5000/login -H "Content-Type: application/json" -d "{\"username\": \"aastha2\", \"password\": \"test\"}"
HTTP/1.1 403 FORBIDDEN
Server: Werkzeug/3.0.1 Python/3.12.1
Date: Sat, 24 Feb 2024 08:05:37 GMT
Content-Type: application/json
Content-Length: 52
Connection: close

{
  "message": "Account locked. Try again later."
}
```

### Secure password requirement:
```
curl -i -X POST http://localhost:5000/register -H "Content-Type: application/json" -d "{\"username\": \"random_user\", \"password\": \"user\"}"
HTTP/1.1 400 BAD REQUEST
Server: Werkzeug/3.0.1 Python/3.12.1
Date: Tue, 27 Feb 2024 08:26:32 GMT
Content-Type: application/json
Content-Length: 162
Connection: close

{
  "message": "Password must be at least 12 characters and include at least one uppercase letter, one lowercase letter, one digit, and one special character."
}
```

```
curl -i -X POST http://localhost:5000/register -H "Content-Type: application/json" -d "{\"username\": \"random_user\", \"password\": \"RandomUser##123\"}"            
HTTP/1.1 201 CREATED
Server: Werkzeug/3.0.1 Python/3.12.1
Date: Tue, 27 Feb 2024 08:27:37 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 0
Connection: close
```

```
curl -i -X POST http://localhost:5000/changepw -H "Content-Type: application/json" -d "{\"username\": \"random_user\", \"old_password\": \"RandomUser##123\",\"new_password\":\"RandomUser@@123\"}"
HTTP/1.1 201 CREATED
Server: Werkzeug/3.0.1 Python/3.12.1
Date: Tue, 27 Feb 2024 08:28:39 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 0
Set-Cookie: session_token=b23921aa-5740-4e45-9182-2d765005b63b; Secure; HttpOnly; Path=/; SameSite=Lax
Connection: close
```

# To do:

1. Check if all endpoints are working correctly as I haven't tested them yet (tested register and login) ✅
2. Add remaining 3 endpoints and test it ✅
3. Secure the code ✅
4. Clean up code - Add comments/ formatting ✅
 

