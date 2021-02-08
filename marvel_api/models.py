from marvel_api import app, db, login_manager, ma
import uuid
from datetime import datetime

from werkzeug.security import generate_password_hash, check_password_hash

import secrets

from flask_login import UserMixin

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

class User(db.Model, UserMixin):
    id = db.Column(db.String, primary_key = True)
    first_name = db.Column(db.String(150), nullable = True, default = '')
    last_name = db.Column(db.String(150), nullable = True, default = '')
    email = db.Column(db.String(150), nullable = False)
    password = db.Column(db.String, nullable = True, default = '')
    g_auth_verify = db.Column(db.Boolean, default = False)
    token = db.Column(db.String, default = '', unique = True)
    date_created = db.Column(db.DateTime, nullable = False, default = datetime.utcnow)
    character = db.relationship('Character', backref = 'owner', lazy = True)


    def __init__(self,email,first_name = '', last_name = '', id = '', password = '', token = '', g_auth_verify = False):
        self.id = self.set_id()
        self.first_name = first_name
        self.last_name = last_name
        self.password = self.set_password(password)
        self.email = email
        self.token = self.set_token(24)
        self.g_auth_verify = g_auth_verify

    def set_token(self,length):
        return secrets.token_hex(length)

    def set_id(self):
        return str(uuid.uuid4())

    def set_password(self, password):
        self.pw_hash = generate_password_hash(password)
        return self.pw_hash
    
    def __repr__(self):
        return f'User {self.email} has been added to the database'

class Character(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    current_alias = db.Column(db.String(150), nullable = False)
    real_name = db.Column(db.String(150), nullable = True, default = '')
    origin = db.Column(db.String(150), nullable = True, default = '')
    universe = db.Column(db.String(150), nullable = True, default = '')
    power = db.Column(db.String(150), nullable = True, default = '')
    comics_appeared_in = db.Column(db.Integer, nullable = True, default = 0)
    date_created = db.Column(db.DateTime, nullable = False, default = datetime.utcnow)
    user_id = db.Column(db.String, db.ForeignKey('user.token'), nullable = False)

    def __init__(self,current_alias,real_name,origin,universe,power,comics_appeared_in,user_id):
        self.current_alias = current_alias
        self.real_name = real_name
        self.origin = origin
        self.universe = universe
        self.power = power
        self.comics_appeared_in = comics_appeared_in
        self.user_id = user_id

    def __repr__(self):
        return self.current_alias

    def to_dict(self):
        return {
            "id": self.id,
            "current_alias": self.current_alias,
            "real_name": self.real_name,
            "origin": self.origin,
            "universe": self.universe,
            "power": self.power,
            "comics_appeared_in": self.comics_appeared_in,
            "date_created": self.date_created,
        }

class CharacterSchema(ma.Schema):
    class Meta:
        fields = ['id', 'current_alias', 'real_name', 'origin', 'universe', 'power', 
            'comics_appeared_in']

character_schema = CharacterSchema()
characters_schema = CharacterSchema(many = True)