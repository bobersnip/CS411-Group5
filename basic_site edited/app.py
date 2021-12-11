######################################
# author ben lawson <balawson@bu.edu>
# Edited by: Craig Einstein <einstein@bu.edu>
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

# for image uploading
import os


app = Flask(__name__)

# check for the database file
if os.path.exists('../database/recipe_app.db'):
    pass
else:
    open("../database/recipe_app.db", "x")

# These will need to be changed according to your creditionals
username = "cs411"
password = "bestclassever"
server = "127.0.0.1"

app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+mysqlconnector://{}:{}@{}/cs411".format(
    username, password, server)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.secret_key = 'ayyylmao'  # Change this!

db = SQLAlchemy(app)


# setting up OAuth
oauth = OAuth(app)

# Google config
# we should make an env file for these later, otherwise you have to manually set environment variables for this to work
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", None)
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", None)
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration")
google = oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
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
        return render_template('hello.html', name=email, message='Account Created!')


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
            return redirect(url_for('login'))

    # information did not match
    return "<a href='/login'>Try again</a>\
			</br><a href='/register'>or make an account</a>"


@app.route('/login/oauth', methods=['GET', 'POST'])
def loginOAuth():
    google = oauth.create_client('google')
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route('/authorize')
def authorize():
    google = oauth.create_client('google')
    token = google.authorize_access_token()
    resp = google.get('userinfo', token=token)
    user_info = resp.json()
    # do something with the token and profile
    return redirect('/')


@app.route('/profile')
def profile():
    curr_user = flask_login.current_user
    user_email = curr_user.get_id()
    # TODO UPDATE THIS WITH FRIEND INFO?
    # TODO UPDATE THIS WITH FAVORITED RECIPES
    # TODO UPDATE THIS WITH CURRENT INGREDIENTS THE USER HAS

    return render_template('profile.html', name=user_email)


@app.route('/login/callback')
def callback():
    pass


@app.route('/logout')
def logout():
    flask_login.logout_user()
    return render_template('hello.html', message='Logged out', top_users=getTopScoreUsers())


@login_manager.unauthorized_handler
def unauthorized_handler():
    return render_template('unauth.html')

# you can specify specific methods (GET/POST) in function header instead of inside the functions as seen earlier


@app.route("/api_req", methods=['GET'])
def api_req():
    return render_template('api_req.html')


@app.route("/api_req", methods=['POST'])
def make_req():
    try:
        URL = "https://api.edamam.com/api/recipes/v2?type=public&"
        api_key_append = "&app_id=4c5b6d9d&app_key=09c2de772eaeb7fd5d30b135fb041c8f"
        ingredients = request.form.get('ingredients')
        ingredients = "q=" + ingredients
        query_url = URL + ingredients + api_key_append
        print(query_url)
        response = requests.get(query_url)
        # print(response.text["hits"])

        recipe_name = []
        recipe_image = []
        recipe_ingredients = []
        index = [x for x in range(20)]

        api_data = json.loads(response.text)["hits"][0:20]
        for hit in api_data:
            recipe_name += [hit["recipe"]["label"]]
            # print(recipe_name)
            recipe_image += [hit["recipe"]["image"]]
            # print(recipe_image)
            recipe_ingredients += [hit["recipe"]["ingredientLines"]]
            # print(recipe_ingredients)

        return render_template('req_display.html', recipe_name=recipe_name, recipe_image=recipe_image, recipe_ingredients=recipe_ingredients, index=index)

        # Do something here :XXXXXXXXXXXXXXXXXXXXXXXXx

    except:
        # this prints to shell, end users will not see this (all print statements go to shell)
        print("couldn't find all tokens")
        return flask.redirect(flask.url_for('api_req'))


@ app.route("/req_display", methods=['GET'])
def req_display():
    return render_template('req_diplay.html')


# home page
@ app.route("/", methods=['GET'])
def hello():
    curr_user = flask_login.current_user
    if curr_user.is_authenticated == True:
        return render_template('hello.html', message='Welcome to the Economic Recipe Finder!')
    else:
        return render_template('hello.html')


if __name__ == "__main__":
    # this is invoked when in the shell  you run
    # $ python app.py
    app.run(port=5000, debug=True)
