# Install virtual env:

`pipenv install`

# Activate it

`pipenv shell`

# How to test endpoint:

Run `python app.py` in a command line with the venv activated.

In another command line, run `curl -X POST http://localhost:5000/register -H "Content-Type: application/json" -d "{\"username\": \"aastha\", \"password\": \"user\"}"` to test any endpoint (in this case I am testing the `/register` endpoint)

You can see the response of the `curl` command in the `app.log` file or in the command line itself (depending on the request).

### Example of app.log:

![alt text](/images/app_log.png)

# To do:

1. Check if all endpoints are working correctly as I haven't tested them yet (tested register and login) ✅
2. Add remaining 3 endpoints and test it
3. Secure the code by adding logging. I also saw something called Talisman but not sure if it helps
4. Clean up code - Add .gitignore /comments/ formatting
5. Need to set up docker to containerize it (?) 

