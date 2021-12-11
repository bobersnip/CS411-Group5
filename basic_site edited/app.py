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

import flask
from flask import Flask, Response, request, render_template, redirect, url_for
from flaskext.mysql import MySQL
import flask_login
import requests
import json
import sqlite3


# for image uploading
import os
import base64


mysql = MySQL()
app = Flask(__name__)
app.secret_key = 'ayyylmao'  # Change this!

# setting up OAuth
from authlib.integrations.flask_client import OAuth
oauth = OAuth(app)

# Google config
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", None) # we should make an env file for these later, otherwise you have to manually set environment variables for this to work
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", None)
GOOGLE_DISCOVERY_URL = ("https://accounts.google.com/.well-known/openid-configuration")
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

# These will need to be changed according to your creditionals
app.config['MYSQL_DATABASE_USER'] = 'USER'
app.config['MYSQL_DATABASE_PASSWORD'] = 'PASSWORD-'
app.config['MYSQL_DATABASE_DB'] = 'photoshare'
app.config['MYSQL_DATABASE_HOST'] = 'localhost'
mysql.init_app(app)

# begin code used for login
login_manager = flask_login.LoginManager()
login_manager.init_app(app)

conn = mysql.connect()
cursor = conn.cursor()
cursor.execute("SELECT email from Users")
users = cursor.fetchall()


def getUserList():
    cursor = conn.cursor()
    cursor.execute("SELECT email from Users")
    return cursor.fetchall()


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
    cursor = mysql.connect().cursor()
    cursor.execute(
        "SELECT password FROM Users WHERE email = '{0}'".format(email))
    data = cursor.fetchall()
    pwd = str(data[0][0])
    user.is_authenticated = request.form['password'] == pwd
    return user


'''
A new page looks like this:
@app.route('new_page_name')
def new_page_function():
	return new_page_html
'''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if flask.request.method == 'GET':
        return '''
			   <form action='login' method='POST'>
				<input type='text' name='email' id='email' placeholder='email'></input>
				<input type='password' name='password' id='password' placeholder='password'></input>
				<input type='submit' name='submit'></input>
			   </form></br>
               or sign in using <a href='/login/oauth'>Google</a>! <br><br>
		   <a href='/'>Home</a>
			   '''
    # The request method is POST (page is recieving data)
    email = flask.request.form['email']
    cursor = conn.cursor()
    # check if email is registered
    if cursor.execute("SELECT password FROM Users WHERE email = '{0}'".format(email)):
        data = cursor.fetchall()
        pwd = str(data[0][0])
        if flask.request.form['password'] == pwd:
            user = User()
            user.id = email
            flask_login.login_user(user)  # okay login in user
            # protected is a function defined in this file
            return flask.redirect(flask.url_for('protected'))

    # information did not match
    return "<a href='/login'>Try again</a>\
			</br><a href='/register'>or make an account</a>"

@app.route('/login/oauth', methods=['GET', 'POST'])
def loginOAuth():
    google = oauth.create_client('google')
    redirect_uri = url_for('authorize', _external = True)
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
    pass

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

    # cursor = conn.cursor()
    # test = isEmailUnique(email)
    # if test:
    # 	print(cursor.execute("INSERT INTO Users (first_name, last_name, email, birth_date, hometown, gender, password, score)"
    # 						 "VALUES ('{0}', '{1}', '{2}', '{3}', '{4}', '{5}', '{6}', '{7}')".format(first_name, last_name, email, birth_date, hometown, gender, password, 0)))

    # 	# Remember to edit this ^^^^ print statement for the insert!!!!!!!!!!!

    # 	conn.commit()
    # 	#log user in
    # 	user = User()
    # 	user.id = email
    # 	flask_login.login_user(user)
    # 	return render_template('hello.html', name=email, message='Account Created!', top_users=getTopScoreUsers())
    # else:


# home page
@ app.route("/", methods=['GET'])
def hello():
    return render_template('hello.html', message='Welcome to the Economic Recipe Finder!')

if __name__ == "__main__":
    # this is invoked when in the shell  you run
    # $ python app.py
    app.run(port=5000, debug=True)
