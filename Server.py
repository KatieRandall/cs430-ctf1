#This file contains the code to start the server and handle each URL request
from flask import Flask
from flask import request
from flask import make_response
from flask import session
import sqlite3
import sys
from Crypto.Hash import SHA256

app = Flask(__name__)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SECRET_KEY'] = 'reds209ndsldssdsljdsldsdsljdsldksdksdsdfsfsfsfis' #TODO: research most secure way to store this
app.config["SESSION_PERMANENT"] = False #TODO: research having a timeout on the cookies

@app.route('/register.php',methods=['GET']) 
def register():
    """creates a new account for user A with pass B in the system."""

    #collect username and password data from url
    username = str(request.args.get("user"))
    password = request.args.get("pass")
    initial_balance = 0

    #hash password
    password_hash = SHA256.new()
    password_hash.update(password.encode())

    #add username and hash of password to database
    con = sqlite3.connect("user_database.db")
    cur = con.cursor()
    data = [(username,password_hash.digest(),initial_balance),]
    cur.executemany("INSERT INTO users VALUES(?, ?, ?)", data)
    con.commit()
    res = cur.execute("SELECT username FROM users")
    print(res.fetchall())

    return "Success: Registered user: " + str(username)

@app.route('/login.php') 
def login():
    """validates the user login and serves the user a cookie"""

    #collect username and password data from url
    username = str(request.args.get("user"))
    password = request.args.get("pass")

    #load password hash from database
    con = sqlite3.connect("user_database.db")
    cur = con.cursor()
    res = cur.execute("SELECT password FROM users WHERE username=(?)", username)
    stored_password_hash = res.fetchone()[0]

    #check if login is valid
    password_hash = SHA256.new()
    password_hash.update(password.encode())
    if password_hash.digest() != stored_password_hash:
        return "Error: Incorrect password"

    #serve user a cookie
    session['logged_in'] = True
    session['username'] = username

    return "Success: Logged in user: " + str(username)

@app.route('/manage.php') 
def manage():
    """performs action C with amount D. Below are the possible combinations of action and amount:
        action=deposit, amount=D - add amount D to the user's account and display balance
        action=withdraw, amount=D - withdraw amount D from the user's acc if there are sufficient funds and display bal
        action=balance, no amount variable specified - print out balance from the user's account
        action=close, no amount variable specified - close out the user's account"""

    #Collect information from URL
    action = request.args.get("action")
    amount = request.args.get("amount")
#Check for cookie
    if 'logged_in' not in session:
        return "Error: Invalid session, please log in again"

    #Connect to database
    connect = sqlite3.connect("user_database.db")
    cursor = connect.cursor()
    balance = cursor.execute("SELECT balance FROM users WHERE username=(?)", session['username']).fetchone()[0]

    #Deposit
    if(str(action) == "deposit"):
        new_balance = balance + int(amount)
        data = [new_balance, session['username']]
        cursor.execute("UPDATE users SET balance=(?) WHERE username=(?)", data)
        connect.commit()
        return "Success: Balance=" + str(new_balance)

    #Withdraw
    if(str(action) == "withdraw"):
        new_balance = balance - int(amount)
        data = [new_balance, session['username']]
        cursor.execute("UPDATE users SET balance=(?) WHERE username=(?)", data)
        connect.commit()
        return "Success: Balance=" + str(new_balance)

    #Balance
    if(str(action) == "Balance"):
        return "Success: Balance=" + str(balance)

    #Close
    if(str(action) == "Close"):
        cursor.execute("DELETE FROM users WHERE username=(?)", session['username'])
        session.pop('logged_in')
        session.pop('username')
        return "Success: Account closed"

    return "Error"

@app.route('/logout.php') 
def logout():
    #Invalidate cookie
    session.pop('logged_in')
    session.pop('username')
    return "Success: Logged out"

if __name__ == '__main__':
    app.run()
