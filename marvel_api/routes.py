from marvel_api import app, db, oauth

import os

from marvel_api.helpers import get_jwt, token_required, verify_owner

from flask import render_template, request, redirect, url_for, flash, session, jsonify

from marvel_api.forms import UserLoginForm, UserSignupForm
from marvel_api.models import User, check_password_hash, Character, character_schema, characters_schema
from datetime import datetime

# imports for flask login
from flask_login import login_user, logout_user, current_user, login_required

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/signup', methods = ['GET', 'POST'])
def signup():
    form = UserSignupForm()

    email = form.email.data
    if User.query.filter(User.email == email).first():
        flash('An account with that email address already exists', 'email-in-use')
        return render_template('signup.html', form=form, signup=True)

    try:
        if request.method == 'POST' and form.validate_on_submit():
            email = form.email.data
            password = form.password.data
            first_name = form.first_name.data.lower()
            last_name = form.last_name.data.lower()
            print(email,password)

            user = User(email, first_name, last_name, password = password)

            db.session.add(user)
            db.session.commit()

            return redirect(url_for('signin'))

        elif request.method == 'POST' and not form.validate_on_submit():
            flash('Invalid email address', 'invalid-email')

    except:
        raise Exception('Invalid Form Data: Please Check Your Form')

    return render_template('signup.html', form=form, signup=True)



@app.route('/signin', methods = ['GET', 'POST'])
def signin():
    form = UserLoginForm()

    try:
        if request.method == 'POST' and form.validate_on_submit():
            email = form.email.data
            password = form.password.data
            print(email,password)

            logged_user = User.query.filter(User.email == email).first()
            if logged_user and check_password_hash(logged_user.password, password):
                login_user(logged_user)
                flash('You were successfully logged in: via Email/Password', 'auth-success')
                return redirect(url_for('profile'))
            else:
                flash('Your Email/Password is incorrect', 'auth-failed')
                return redirect(url_for('signin'))
        elif request.method == 'POST' and not form.validate_on_submit():
            flash('Invalid email address', 'invalid-email')

    except:
        raise Exception('Invalid Form Data: Please Check Your Form')

    return render_template('signin.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    if session:
        for key in list(session.keys()):
            session.pop(key)
    return redirect(url_for('home'))

@app.route('/profile', methods = ['GET'])
@login_required
def profile():
    jwt = get_jwt(current_user)
    return render_template('profile.html', jwt = jwt)

@app.route('/api_doc')
def api_doc():
    return render_template('api_doc.html')

@app.route('/pricing')
def pricing():
    return render_template('pricing.html')

@app.route('/support')
def support():
    return render_template('support.html')

# CREATE CHARACTER ENDPOINT
@app.route('/characters', methods = ['POST'])
@token_required
def create_character(current_user_token):
    print(current_user_token)
    current_alias = request.json['current_alias']
    real_name = request.json['real_name']
    origin = request.json['origin']
    universe = request.json['universe']
    power = request.json['power']
    comics_appeared_in = request.json['comics_appeared_in']
    
    user_id = current_user_token.token

    character = Character(current_alias,real_name,origin,universe,power,comics_appeared_in, 
        user_id = user_id)

    db.session.add(character)
    db.session.commit()

    response = character_schema.dump(character)
    return jsonify(response)

# RETRIEVE ALL CHARACTERS ENDPOINT
@app.route('/characters', methods = ['GET'])
@token_required
def get_characters(current_user_token):
    owner, current_user_token = verify_owner(current_user_token)
    characters = Character.query.filter_by(user_id = owner.user_id).all()
    response = characters_schema.dump(characters)
    return jsonify(response)

# RETRIEVE ONE CHARACTER ENDPOINT
@app.route('/characters/<id>', methods = ['GET'])
@token_required
def get_character(current_user_token, id):
    owner, current_user_token = verify_owner(current_user_token)
    character = Character.query.get(id)
    response = character_schema.dump(character)
    return jsonify(response)

# UPDATE CHARACTER ENDPOINT
@app.route('/characters/<id>', methods = ['POST','PUT'])
@token_required
def update_character(current_user_token,id):
    owner, current_user_token = verify_owner(current_user_token)
    character = Character.query.get(id) # GET CHARACTER INSTANCE

    character.current_alias = request.json['current_alias']
    character.real_name = request.json['real_name']
    character.origin = request.json['origin']
    character.universe = request.json['universe']
    character.power = request.json['power']
    character.comics_appeared_in = request.json['comics_appeared_in']

    db.session.commit()
    response = character_schema.dump(character)
    return jsonify(response)

# DELETE CHARACTER ENDPOINT
@app.route('/characters/<id>', methods = ['DELETE'])
@token_required
def delete_character(current_user_token,id):
    owner, current_user_token = verify_owner(current_user_token)
    character = Character.query.get(id)
    db.session.delete(character)
    db.session.commit()
    response = character_schema.dump(character)
    return jsonify(response)

# Google OAuth routes and config info
google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',  # This is only needed if using openId to fetch user info
    client_kwargs={'scope': 'openid email profile'},
)

@app.route('/google-auth')
def google_auth():
    google = oauth.create_client('google')
    redirect_uri = url_for('authorize', _external = True)
    return google.authorize_redirect(redirect_uri)

@app.route('/authorize')
def authorize():
    google = oauth.create_client('google')
    token = google.authorize_access_token()
    response = google.get('userinfo')
    user_info = response.json()
    user = oauth.google.userinfo()
    session['profile'] = user_info

    user = User.query.filter_by(email = user_info['email']).first()
    if user:
        login_user(user)
        session.permanent = True
        return redirect(url_for('profile'))

    else:
        g_first_name = user_info['given_name'].lower()
        g_last_name = user_info['family_name'].lower()
        g_email = user_info['email']
        g_verified = user_info['verified_email']

        user = User(
            first_name = g_first_name,
            last_name = g_last_name,
            email = g_email,
            g_auth_verify = g_verified
        )

        db.session.add(user)
        db.session.commit()
        session.permanent = True
        login_user(user)
        return redirect(url_for('profile'))

    print(user_info)
    return redirect(url_for('home'))