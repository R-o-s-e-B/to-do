import os

from flask import Flask, redirect, render_template, url_for, request, flash
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from sqlalchemy import Column, Integer, ForeignKey

XP = 10

app = Flask(__name__)

app.config["SECRET_KEY"] = "shdhuidwiejdlienfkjesjfio"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///accounts.db"
app.config["TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100))
    level = db.Column(db.Integer, nullable=False, default=1)
    xp = db.Column(db.Integer, nullable=False, default=0)
    task_no = db.Column(db.Integer, default=0)
    profile_img = db.Column(db.String(500))
    img_change = db.Column(db.Integer, default=0)
    tasks = relationship("Tasks", back_populates="user")



class Tasks(db.Model):
    __tablename__ = "tasks"
    id = db.Column(db.Integer, primary_key=True)
    task_id = Column(Integer, ForeignKey('users.id'))
    task_to_do = db.Column(db.String(500))
    tasks_complete = db.Column(db.String(500))
    user = relationship("User", back_populates="tasks")
    complete = db.Column(db.Integer, default=0)
    due = db.Column(db.String(100))
    complete_date = db.Column(db.String(100))

with app.app_context():
    db.create_all()

class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Sign up", validators=[DataRequired()])

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login", validators=[DataRequired()])


@app.route("/")
def home():
    date_today = datetime.today().strftime("%Y-%m-%d")
    tasks = db.session.query(Tasks).order_by(Tasks.due).all()
    return render_template("index.html", tasks=tasks, today=date_today)


@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        if User.query.filter_by(email=request.form['email']).first():
            flash("Email already exists, login")
            return redirect(url_for("login"))

        hash_and_salted = generate_password_hash(request.form["password"], method='pbkdf2:sha256', salt_length=8)

        new_user = User()


        new_user.email = request.form["email"]
        new_user.name = request.form["name"]
        new_user.password = hash_and_salted

        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("home"))
    return render_template("register.html")



@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('home'))
            else:
                flash("Wrong password")
        else:
            flash("This email does not exist")
    return render_template("login.html")

@app.route('/add', methods=['GET', 'POST'])
def add():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    elif current_user.is_authenticated:
        if request.method == 'POST':
            new_task = Tasks()
            new_task.task_to_do = request.form['task']
            new_task.task_id = current_user.id
            new_task.due = request.form['due']
            db.session.add(new_task)
            db.session.commit()
        return redirect(url_for("home"))
    return render_template("home")

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/delete', methods=['DELETE', 'GET'])
def delete():
   id = request.args.get('id')
   task_to_del = db.session.query(Tasks).get(id)
   db.session.delete(task_to_del)
   db.session.commit()
   return redirect(url_for('home'))

@app.route('/complete', methods=['GET', 'POST'])
def complete():
    current_date = datetime.today().strftime("%d-%m-%Y")
    id = request.args.get('id')
    completed_task = db.session.query(Tasks).get(id)
    current_user.task_no += 1
    completed_task.complete = 1
    current_user.xp += XP
    if current_user.xp >= (current_user.level + 1)*XP:
        current_user.level += 1
        current_user.xp = 10
    completed_task.complete_date = current_date
    db.session.commit()

    return redirect(url_for('home'))


@app.route('/change', methods=['GET', 'POST'])
def change():
    if request.method == 'POST':
        current_user.img_change = 1
        db.session.commit()
        return redirect(url_for('home'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    current_user.profile_img = request.form.get('pic')
    current_user.img_change = 0
    db.session.commit()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
