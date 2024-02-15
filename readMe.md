# Install virtual env:

`pipenv install`

# Activate it

`pipenv shell`

# How to test endpoint:

Run `python app.py` in a command line with the venv activated.

In another command line, run `curl -X POST http://localhost:5000/register -H "Content-Type: application/json" -d "{\"username\": \"aastha\", \"password\": \"user\"}"` to test any endpoint (in this case I am testing the `/register` endpoint)

# To do:

1. Check if all endpoints are working correctly as I haven't tested them yet
2. Secure the code by adding logging. I also saw something called Talisman but not sure if it helps
3. Clean up code - Add .gitignore /comments/ formatting
4. Need to set up docker to containerize it (?) 

If I test an endpoint continuously, I get `sqlite3.OperationalError: database is locked ` error. Need to have a workaround for this.