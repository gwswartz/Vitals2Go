from flask import Flask, render_template, url_for, redirect, request, make_response
import os
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from time import time
import json
import max30100
from gpiozero import MCP3008
app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
mx30 = max30100.MAX30100()
mx30.enable_spo2()
x = 1
reading = MCP3008(channel=1)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


@app.route('/')
def home():
    return render_template('welcomepage.html')

@app.route('/background',methods=['GET','POST'])
def background():
    return render_template('background.html')

@app.route('/allergies',methods=['GET','POST'])
def allergies():
    return render_template('allergies.html')

@app.route('/message',methods=['GET','POST'])
def message():
    return render_template('message.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/dashboard')
def show_index():
	full_filename = os.path.join(app.config['UPLOAD_FOLDER'],'vitals2go.png')
	full_filename = os.path.join(app.config['UPLOAD_FOLDER'],'alex.png')
	return render_template("index.html",user_image = full_filename)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/data', methods=["GET", "POST"])
def data():
    celsius = round((reading.value * 3.3) * 100, 2)
    fahren = round(celsius * 1.8 + 32, 2) -165
    Temperature = min(99, max(65, fahren))
    if x > 0:
        mx30.read_sensor()
        mx30.ir, mx30.red
        pulseox = int(mx30.red / 100)
        Oximetry = min(99, max (0, pulseox))
        Heartbeat = int(mx30.ir / 100)
    fall = "No"
    spo2 = Oximetry 
    data = [time() * 1000, Temperature, Heartbeat, spo2, fall]
    response = make_response(json.dumps(data))
    response.content_type = 'application/json'

    return response

if __name__ == "__main__":
    app.run(debug=True)
