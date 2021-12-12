
######################################
# Some code adapted from
# CodeHandBook at http://codehandbook.org/python-web-application-development-using-flask-and-mysql/
# and MaxCountryMan at https://github.com/maxcountryman/flask-login/
# and Flask Offical Tutorial at  http://flask.pocoo.org/docs/0.10/patterns/fileuploads/
# and Authlib Documentation at https://docs.authlib.org/en/latest/index.html
# see links for further understanding
###################################################

from authlib.integrations.flask_client import OAuth
import flask
from flask import Flask, Response, request, render_template, redirect, url_for
from flaskext.mysql import MySQL
from sqlalchemy import desc, func, ForeignKey
from sqlalchemy.sql.functions import user
from flask_sqlalchemy import SQLAlchemy
import flask_login
import requests
import json
import sqlite3
import config
import time

# for image uploading
import os
import base64


app = Flask(__name__)


app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+mysqlconnector://{}:{}@{}/cs411".format(
    config.username, config.password, config.server)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['TEMPLATES_AUTO_RELOAD'] = True
# mysql.init_app(app)

app.secret_key = 'ayyylmao'  # Change this!

db = SQLAlchemy(app)


# mySQL database
mysql = MySQL()
app.config['MYSQL_DATABASE_USER'] = 'root'
# change your password for mysql database
app.config['MYSQL_DATABASE_PASSWORD'] = 'Lkh1999426.'

app.config['MYSQL_DATABASE_DB'] = 'cs411'
app.config['MYSQL_DATABASE_HOST'] = 'localhost'
mysql.init_app(app)
conn = mysql.connect()
cursor = conn.cursor()

# setting up OAuth
oauth = OAuth(app)

# Google config
# we should make an env file for these later, otherwise you have to manually set environment variables for this to work
# GOOGLE_CLIENT_ID =
# GOOGLE_CLIENT_SECRET =
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration")
google = oauth.register(
    name='google',
    client_id=config.GOOGLE_CLIENT_ID,
    client_secret=config.GOOGLE_CLIENT_SECRET,
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid profile email'},
)


# Classes declared to generate the database's Schema
class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    first_name = db.Column(db.String(30))
    last_name = db.Column(db.String(30))


class Friends(db.Model):
    user_id1 = db.Column(db.Integer, ForeignKey(
        'users.id'), onupdate="CASCADE", primary_key=True)
    user_id2 = db.Column(db.Integer, ForeignKey(
        'users.id'), onupdate="CASCADE", primary_key=True)


class Favorites(db.Model):
    user = db.Column(db.String(100), ForeignKey(
        'users.email'), onupdate="CASCADE", primary_key=True)
    name = db.Column(db.String(100), primary_key=True)
    ingredients = db.Column(db.Text(10000))


db.create_all()

# begin code used for login
login_manager = flask_login.LoginManager()
login_manager.init_app(app)


def getUserList():
    users_unfiltered = Users.query.all()
    users = []
    for x in users_unfiltered:
        users.append(x.email)
    return users


class User(flask_login.UserMixin):
    pass


@login_manager.user_loader
def user_loader(email):
    users = getUserList()
    if not(email) or email not in str(users):
        return
    user = User()
    user.id = email
    return user


@login_manager.request_loader
def request_loader(request):
    users = getUserList()
    email = request.form.get('email')
    if not(email) or email not in str(users):
        return
    user = User()
    user.id = email
    # cursor = mysql.connect().cursor()
    # cursor.execute(
    #     "SELECT password FROM Users WHERE email = '{0}'".format(email))
    # data = cursor.fetchall()
    data = db.session.query(
        "password FROM Users WHERE email = '{0}'".format(email))
    if data != None:
        pwd = str(data[0][0])
        user.is_authenticated = request.form['password'] == pwd
        return user
    else:
        return


'''
A new page looks like this:
@app.route('new_page_name')
def new_page_function():
	return new_page_html
'''


def email_is_registered(email):
    data = db.session.query(
        "email  FROM Users WHERE email = '{0}'".format(email)).first()
    if data == None:
        return False
    else:
        return True


@app.route('/register', methods=['GET', 'POST'])
def register():
    if flask.request.method == 'GET':
        return render_template('register.html')

    # if the method is POST, the user is trying to send registration info
    try:
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        # TODO I THINK WE ARE SUPPOSED TO HASH THE PASSWORD BEFORE STORING IT
        password = request.form.get('password')
    except:
        # this prints to shell, end users will not see this (all print statements go to shell)
        print("couldn't find all tokens")
        return redirect(url_for('register'))
    # test if the user's email is already registered
    if (not email_is_registered(email)):
        # add user to the db
        new_user = Users(first_name=first_name,
                         last_name=last_name, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()

        # for flask login
        user = User()
        user.id = email
        flask_login.login_user(user)
        return render_template('hello.html', name=email, message='Account Created!', logged_in=True)


@app.route('/login', methods=['GET', 'POST'])
def login():
    # if the method is GET, the user is trying to get to the login page
    if flask.request.method == 'GET':
        return render_template('login.html')

    # if the request method is POST, the user is sending login data
    email = flask.request.form['email']

    # check if email is registered
    data = db.session.query(
        "password FROM Users WHERE email = '{0}'".format(email)).first()
    print(data)
    if data != None:
        pwd = str(data[0])
        if flask.request.form['password'] == pwd:
            user = User()
            user.id = email
            flask_login.login_user(user)  # okay login in user
            # protected is a function defined in this file
            return redirect('/')

    # information did not match
    return render_template('failLogin.html')


@ app.route('/login/oauth', methods=['GET', 'POST'])
def loginOAuth():
    google = oauth.create_client('google')
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)


@ app.route('/authorize')
def authorize():
    google = oauth.create_client('google')
    token = google.authorize_access_token()
    resp = google.get('userinfo', token=token)
    user_info = resp.json()
    # do something with the token and profile
    return redirect('/')


@ app.route('/profile')
@ flask_login.login_required
def profile():
    curr_user = flask_login.current_user
    user_email = curr_user.get_id()

    # TODO UPDATE THIS WITH FRIEND INFO?
    # TODO UPDATE THIS WITH FAVORITED RECIPES
    # TODO UPDATE THIS WITH CURRENT INGREDIENTS THE USER HAS

    return render_template('profile.html', name=user_email)


@app.route("/favorite")
@flask_login.login_required
def get_user_favorite_recipe():
    cursor = conn.cursor()
    cursor.execute(("SELECT * FROM favorites"))
    data = cursor.fetchall()
    return render_template('favorite.html', data=data)


@ app.route('/login/callback')
def callback():
    pass


@ app.route('/logout')
def logout():
    flask_login.logout_user()
    return render_template('hello.html', message='Logged out', logged_in=False)


@ login_manager.unauthorized_handler
def unauthorized_handler():
    return render_template('unauth.html')

# you can specify specific methods (GET/POST) in function header instead of inside the functions as seen earlier


@ app.route("/api_req", methods=['GET'])
def api_req():
    return render_template('api_req.html')


@ app.route("/api_req", methods=['POST'])
def make_req():
    start = time.time()
    URL = "https://api.edamam.com/api/recipes/v2?type=public&"
    api_key_append = "&app_id=4c5b6d9d&app_key=09c2de772eaeb7fd5d30b135fb041c8f"
    ingredients = request.form.get('ingredients')
    ingredients = "q=" + ingredients
    query_url = URL + ingredients + api_key_append
    # print(query_url)
    response = requests.get(query_url)
    # print(response.text["hits"])
    recipe_name = []
    recipe_image = []
    recipe_ingredients = []
    index = [x for x in range(20)]

    # kroger api stuff

    # Get access token from kroger
    kroger_client_id = "recipeingredientsprices-b099514b5746a51f59bb2aaab456e0886003954412832050940"
    kroger_client_secret = "yhSnzXMzYTgRRDy0eW3UjaCKALD4FqDE3s2Y6Deu"
    id_encode = kroger_client_id + ":" + kroger_client_secret
    id_encode = id_encode.encode("ascii")
    kroger_client_id64 = base64.b64encode(id_encode)
    k64u = kroger_client_id64.decode("ascii")
    url_kroger_access = "https://api.kroger.com/v1/connect/oauth2/token"
    payload_kroger_access = {
        "grant_type": "client_credentials", "scope": "product.compact"}
    headers_kroger_access = {'Authorization': 'Basic ' + k64u,
                             'Content-Type': 'application/x-www-form-urlencoded'}
    response_kroger = requests.request(
        "POST", url_kroger_access, headers=headers_kroger_access, data=payload_kroger_access)
    access_token = json.loads(response_kroger.text)["access_token"]

    # set up for the prices api call for kroger
    url_prices = "https://api.kroger.com/v1/products?filter.term="
    payload_prices = {}
    header_prices = {"Accept": "application/json",
                     "Authorization": "Bearer " + access_token}

    prices_sorter = []
    api_data = json.loads(response.text)["hits"][0:20]
    for i in range(len(api_data)):

        # make sure no duplicate ingredients appear
        ingredients_list = []
        [ingredients_list.append(x["text"]) for x in api_data[i]["recipe"]
         ["ingredients"] if x["text"] not in ingredients_list]
        ingredientLines_list = []
        [ingredientLines_list.append(
            x) for x in api_data[i]["recipe"]["ingredientLines"] if x not in ingredientLines_list]

        num_ingredients = min(len(ingredients_list), len(ingredientLines_list))
        recipe_ingredients += [[0]*(num_ingredients+1)]

        recipe_price = 0.00
        for j in range(num_ingredients):
            ingredient_search = api_data[i]["recipe"]["ingredients"][j]["food"]

            try:
                # get the price of the current ingredient
                response_prices = requests.request(
                    "GET", url_prices + ingredient_search + "&filter.locationId=01400943&filter.limit=1", headers=header_prices, data=payload_prices, timeout=3)

                try:
                    response_prices_json = json.loads(response_prices.text)
                    price_float = round(
                        response_prices_json["data"][0]["items"][0]["price"]["regular"], 3)
                    recipe_price += price_float
                    price_string = str(price_float)
                    print(price_string)
                    recipe_ingredients[i][j] = api_data[i]["recipe"]["ingredientLines"][j] + \
                        " Price: $" + price_string
                except:
                    print("data not found")
                    recipe_ingredients[i][j] = api_data[i]["recipe"]["ingredientLines"][j] + \
                        " Price: N/A not found"
            except requests.exceptions.Timeout as err:
                print("data not found")
                recipe_ingredients[i][j] = api_data[i]["recipe"]["ingredientLines"][j] + \
                    " Price: N/A took too long to respond"

            print()
            print(recipe_ingredients[i][j])
            print("done")
        print("recipe total = $" + str(recipe_price))
        recipe_name += [api_data[i]["recipe"]["label"]]
        recipe_image += [api_data[i]["recipe"]["image"]]
        recipe_ingredients[i][num_ingredients] = "Total recipe price = $" + \
            str(round(recipe_price, 3))
        prices_sorter += [[i, round(recipe_price, 3)]]

    # Sorting recipies based on price
    prices_sorter = sorted(prices_sorter, key=lambda x: x[1])
    names_sorted = []
    images_sorted = []
    recipe_sorted = []
    for i in range(len(prices_sorter)):
        names_sorted += [recipe_name[prices_sorter[i][0]]]
        images_sorted += [recipe_image[prices_sorter[i][0]]]
        recipe_sorted += [recipe_ingredients[prices_sorter[i][0]]]

    end = time.time()
    print("The search took " + str(end - start) + " seconds!")

    return render_template('req_display.html', recipe_name=names_sorted, recipe_image=images_sorted, recipe_ingredients=recipe_sorted, index=index)


@ app.route("/favorite/<recipe_name>/", methods=['GET', 'POST'])
@ flask_login.login_required
def add_to_favorites(recipe_name):
    URL = "https://api.edamam.com/api/recipes/v2?type=public&"
    api_key_append = "&app_id=4c5b6d9d&app_key=09c2de772eaeb7fd5d30b135fb041c8f"
    recipe = "q=" + recipe_name
    query_url = URL + recipe + api_key_append
    print(query_url)
    response = requests.get(query_url)
    # print(response.text["hits"])

    api_data = json.loads(response.text)["hits"][0]
    recipe_image = api_data["recipe"]["image"]
    recipe_ingredients = api_data["recipe"]["ingredientLines"]
    ingredients = ""
    for ingredient in recipe_ingredients:
        ingredients += ("{}, ".format(ingredient))

    # print("ingredients: " + ingredients)
    curr_user = flask_login.current_user.get_id()
    # print("current_user: " + curr_user)
    # try to add the entry, it may already be in the favorites
    try:
        new_favorite = Favorites(
            user=curr_user, name=recipe_name, ingredients=ingredients)
        db.session.add(new_favorite)
        db.session.commit()
        return render_template('api_req.html', message=recipe_name + " added to favorites")
    except:
        return render_template('api_req.html', message="recipe already in favorites, or another error occurred.")


@ app.route("/req_display", methods=['GET'])
def req_display():
    return render_template('req_diplay.html')


# home page
@ app.route("/", methods=['GET'])
def hello():
    curr_user = flask_login.current_user
    if curr_user.is_authenticated == True:
        return render_template('hello.html', message='Welcome to the Economic Recipe Finder!', logged_in=True)
    else:
        return render_template('hello.html', logged_in=False)


if __name__ == "__main__":
    # this is invoked when in the shell  you run
    # $ python app.py
    app.run(port=5000, debug=True)
