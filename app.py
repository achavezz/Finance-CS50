import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session["user_id"]
    stocks = db.execute(
        "SELECT symbol, name, price, SUM(shares) as totalShares FROM transactions WHERE user_id = ? GROUP BY symbol", user_id)
    cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
    total = cash

    for stock in stocks:
        #current_stock_price = lookup(stock["symbol"])["price"]
        #total += current_stock_price * stock["totalShares"]
        total += stock["price"] * stock["totalShares"]

    return render_template("index.html", stocks=stocks, cash=cash, usd=usd, total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol").upper()
        if not symbol:
            return apology("must provide a company's symbol")

        try:
            shares = int(request.form.get("shares"))
        except:
            return apology("shares must be an integer")

        if shares <= 0:
            return apology("shares must be a positive integer")
        quote = lookup(symbol)
        if not quote:
            return apology("ivalid symbol")

        user_id = session["user_id"]
        cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
        share_name = quote["name"]
        share_price = quote["price"]
        total_share_price = share_price * shares

        if cash < total_share_price:
            return apology("not enough cash")
        else:
            db.execute("UPDATE users SET cash = ? WHERE id = ?", cash - total_share_price, user_id)
            db.execute("INSERT INTO transactions (user_id, name, shares, price, type, symbol) VALUES (?, ?, ?, ?, ?, ?)",
                       user_id, share_name, shares, share_price, 'buy', symbol)
            return redirect("/")
    return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]
    transactions = db.execute("SELECT symbol, shares, price, time FROM transactions WHERE user_id = ?", user_id)
    return render_template("history.html", transactions=transactions, usd=usd)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "POST":
        symbol = request.form.get("symbol").upper()
        if not symbol:
            return apology("must provide company symbol")

        quote = lookup(symbol)
        if quote is None:
            return apology("symbol not found")

        return render_template("quoted.html", quote=quote, usq_function=usd)

    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username")

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password")

        # Ensure comfirmation password was submitted
        elif not request.form.get("confirmation"):
            return apology("must comfirm password")

        # Ensure passwords match
        elif not request.form.get("password") == request.form.get("confirmation"):
            return apology("passwords don't match")

        hash = generate_password_hash(request.form.get("password"))
        username = request.form.get("username")

        # Check if username already exists
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        if len(rows) != 0:
            return apology("username already exists")

        # Insert new user in database
        new_user = db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash)

    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    user_id = session["user_id"]

    if request.method == "POST":
        symbol = request.form.get("symbol")

        if not symbol:
            return apology("Please select a company symbol", 403)

        shares = int(request.form.get("shares"))

        item = lookup(symbol)
        item_price = item["price"]
        item_name = item["name"]
        shares_owned = db.execute(
            "SELECT SUM(shares) AS shares FROM transactions WHERE user_id = ? AND symbol = ? GROUP BY symbol", user_id, symbol)[0]["shares"]

        if shares > shares_owned:
            return apology("Not enough shares!")

        profit = shares * item_price
        current_cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
        db.execute("UPDATE users SET cash = ? WHERE id = ?", current_cash + profit, user_id)
        db.execute("INSERT INTO transactions (user_id, name, shares, price, type, symbol) VALUES (?, ?, ?, ?, ?, ?)",
                   user_id, item_name, -shares, item_price, "sell", symbol)
        return redirect('/')

    else:
        symbols = db.execute("SELECT symbol FROM transactions WHERE user_id = ? AND type = ? GROUP BY symbol", user_id, 'buy')
        return render_template("sell.html", symbols=symbols)
