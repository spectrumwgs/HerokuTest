import string
import random

from flask import Flask, render_template, flash, redirect, url_for, make_response
from flask import request
from flask import jsonify
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
from flask_mail import Mail
from flask_mail import Message
from flask_socketio import SocketIO, emit
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    jwt_refresh_token_required, create_refresh_token,
    get_jwt_identity, set_access_cookies,
    set_refresh_cookies, unset_jwt_cookies, verify_jwt_in_request
)
from sqlalchemy import Column, String, Integer, Boolean, desc
from datetime import datetime
import os

# Set up
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///PyTest.db'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root@localhost/PyTest'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.urandom(32)
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_REFRESH_COOKIE_PATH'] = '/token/refresh'
app.config['JWT_COOKIE_CSRF_PROTECT'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'jesusgonzalez.flask@gmail.com'
app.config['MAIL_PASSWORD'] = 'irdsrvhzbumhopto'

# Extras
socketio = SocketIO(app)
db = SQLAlchemy(app)
ma = Marshmallow(app)
jwt = JWTManager(app)
bootstrap = Bootstrap(app)
mail = Mail(app)


# Handlers
@socketio.on('sendMessage')
def send_message(json):
    emit('new_message', json, namespace='/chat', broadcast=True)


# Tables
class Users(db.Model):
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True)
    password = Column(String(255))
    roles = Column(String(255))
    login = Column(String(255))
    is_active = Column(Boolean, default=True)
    confirmed = Column(Boolean, default=False)
    key = Column(String(255))

    def __init__(self, email, password, key):
        self.email = email
        self.password = password
        self.key = key


class Messages(db.Model):
    id = Column(Integer, primary_key=True)
    user = Column(String(255))
    message = Column(String(255))
    posted = Column(String(255))

    def __init__(self, user, message, posted):
        self.user = user
        self.message = message
        self.posted = posted


# Serialization
class UsersSchema(ma.Schema):
    class Meta:
        fields = ('id', 'email', 'password', 'login', 'confirmed')


class MessagesSchema(ma.Schema):
    class Meta:
        fields = ('id', 'user', 'message', 'posted')


# SQLAlchemy
db.create_all()
user_schema = UsersSchema()
users_schema = UsersSchema(many=True)
message_schema = MessagesSchema()
messages_schema = MessagesSchema(many=True)


# Validators
class MyDataRequired(DataRequired):
    field_flags = ()


# Forms
class LoginForm(FlaskForm):
    username = StringField('E-mail', validators=[MyDataRequired(), Email()])
    password = PasswordField('Password', validators=[MyDataRequired()])
    submit = SubmitField('Sign In')
    register = SubmitField('New Account')


class RegisterForm(FlaskForm):
    username = StringField('E-mail', validators=[MyDataRequired(), Email()])
    password = PasswordField('Password', validators=[MyDataRequired()])
    confirm = PasswordField('Repeat Password', validators=[MyDataRequired(), EqualTo('password', 'Passwords must match')])
    submit = SubmitField('Register')
    cancel = SubmitField('Cancel')


class MessageForm(FlaskForm):
    message = StringField('Message', validators=[DataRequired()])
    submit = SubmitField('Send')


# API
@app.route('/user', methods=['GET', 'POST'])
@app.route('/user/', methods=['GET', 'POST'])
def user_main():
    if request.method == 'POST':
        email = request.json['email']
        password = request.json['password']
        key = ''.join(random.choices(string.ascii_uppercase + string.digits, k=9))
        new_user = Users(email, password, datetime.now().strftime("%d/%m/%Y %H:%M"))
        db.session.add(new_user)
        db.session.commit()
        return user_schema.jsonify(new_user)
    else:
        all_users = Users.query.all()
        result = users_schema.dump(all_users)
        return jsonify(result)


@app.route('/user/<query_id>')
def get_user(query_id):
    user = Users.query.filter_by(id=query_id).first()
    return user_schema.jsonify(user)


@app.route('/confirm')
def activate_user():
    key = request.args.get('key')
    user = Users.query.filter_by(key=key).first()
    user.confirmed = 1
    db.session.commit()
    flash('The account has been activated successfully')
    return redirect(url_for('login_page'))


@app.route('/register', methods=['GET', 'POST'])
def register_page():
    form = RegisterForm()
    if form.validate_on_submit():
        if Users.query.filter_by(email=form.username.data).count() == 0:
            key = ''.join(random.choices(string.ascii_uppercase + string.digits, k=9))
            new_user = Users(email=form.username.data, password=form.password.data, key=key)
            db.session.add(new_user)
            db.session.commit()
            msg = Message("Confirm your account", sender=("Flask Service", "jesusgonzalez.flask@gmail.com"))
            msg.recipients = [form.username.data]
            msg.body = "Your account has not been confirmed, to continue click the following link: " + request.url_root.rstrip('/') + "/confirm?key=" + key
            mail.send(msg)
            flash('A verification email has been sent to ' + form.username.data)
            return render_template('registerPageBS.html', title='Flask', form=form)
        else:
            flash('That email is already in use by another account.')
            return render_template('registerPageBS.html', title='Flask', form=form)
    else:
        return render_template('registerPageBS.html', title='Flask', form=form)


@app.route('/', methods=['GET', 'POST'])
def login_page():
    try:
        verify_jwt_in_request()
    except Exception:
        form = LoginForm()
        if form.validate_on_submit():
            try:
                user = Users.query.filter(Users.email == form.username.data, Users.password == form.password.data).first()
            except Exception:
                flash('Wrong email or password.')
                return render_template('loginPageBS.html', title='Flask', form=form)
            if user.confirmed == 1:
                user.login = datetime.now().strftime("%d/%m/%Y %H:%M")
                db.session.commit()
                access_token = create_access_token(identity=form.username.data)
                refresh_token = create_refresh_token(identity=form.username.data)
                resp = make_response(redirect(url_for('protected')))
                set_access_cookies(resp, access_token)
                set_refresh_cookies(resp, refresh_token)
                return resp
            else:
                flash('Your account has not been confirmed, please check your inbox.')
                return render_template('loginPageBS.html', title='Flask', form=form)
        else:
            return render_template('loginPageBS.html', title='Flask', form=form)
    return redirect(url_for('protected'))


@app.route('/index', methods=['GET', 'POST'])
@jwt_required
def protected():
    user = Users.query.filter_by(email=get_jwt_identity()).first()
    form = MessageForm()
    if form.validate_on_submit():
        new_msg = Messages(user=user.email, message=form.message.data, posted=datetime.now().strftime("%d/%m/%Y %H:%M"))
        db.session.add(new_msg)
        db.session.commit()
        return redirect(url_for('protected'))
    last_messages = Messages.query.order_by(desc(Messages.id)).limit(10).all()
    msg_result = messages_schema.dump(last_messages)
    send_message(msg_result.reverse())
    return render_template('mainPageBS.html', title='Flask', form=form, msg=msg_result)


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    resp = jsonify({'logout': True})
    unset_jwt_cookies(resp)
    return resp, 200


if __name__ == '__main__':
    socketio.run(app)
