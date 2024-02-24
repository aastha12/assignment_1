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


# To do:

1. Check if all endpoints are working correctly as I haven't tested them yet (tested register and login) ✅
2. Add remaining 3 endpoints and test it
3. Secure the code by adding logging. I also saw something called Talisman but not sure if it helps
4. Clean up code - Add .gitignore /comments/ formatting
5. Need to set up docker to containerize it (?) 

