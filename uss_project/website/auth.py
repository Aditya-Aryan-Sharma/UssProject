import re
import string
import smtplib
import random
from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from .models import User
from .models import Otp
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user
import os
from dotenv import load_dotenv
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

load_dotenv()
auth = Blueprint('auth', __name__)
regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

def send_otp(user_email):
    otp = int(''.join(random.choices(string.digits, k = 6)))
    s = smtplib.SMTP('smtp.gmail.com', 587)
    s.starttls()
    s.login(os.getenv("email"), os.getenv("password"))
    message = "Here is your verification code for signing up:\n" + str(otp)
    s.sendmail(os.getenv("email"), user_email, message)
    s.quit()
    return otp

def is_not_alpha(s):
    return not any(c.isalpha() and c.islower() or c.isupper() for c in s)

def generate_key(k):
    return str(''.join(random.choices(string.ascii_lowercase + string.ascii_uppercase + string.digits, k = k)))

def generateKey(passcode, email, id):
    session["my_key"] = generate_key(16).encode()
    session["iv"] = generate_key(16).encode()
    generative_key = (str(passcode) + str(email) + str(id)).encode()
    cipher = AES.new(session.get("my_key"), AES.MODE_CBC, session.get("iv"))
    return cipher.encrypt(pad(generative_key, AES.block_size))

@auth.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    message = request.args.get('message', '')
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email = email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember = True)
                session["encrypted_key"] = generateKey(password, email, user.id)
                return redirect(url_for('views.home'))
            else:
                error = "Incorrect password, try again."
        else:
            error = "Email not Registered !"
    return render_template("login.html", user = current_user, error = error, message = message)

@auth.route('/otp/<curr_user>/', methods = ['GET', 'POST'])
def otp(curr_user):
    user = Otp.query.filter_by(user_id = curr_user).first()
    if not user:
        g_otp = generate_password_hash(str(send_otp(curr_user)), method = 'sha256')
        new_entry = Otp(otp = g_otp, user_id = curr_user)
        db.session.add(new_entry)
        db.session.commit()
    if request.method == 'POST':
        passcode = request.form.get('otp')
        auth_code = Otp.query.filter_by(user_id = curr_user).first().otp
        if check_password_hash(auth_code, passcode):
            return redirect(url_for('auth.login', message = 'You can now login to access services.'))
        else:
            logout_user()
            User.query.filter_by(email = curr_user).delete()
            db.session.commit()
            return redirect(url_for('auth.sign_up'))
    return render_template("otp.html", user = current_user, user_email = curr_user)

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    error = None
    logout_user()
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        verified = request.form.get("verified")
        if (verified is not None and verified.capitalize() == "True"):
            verified = True
        elif (verified is not None and verified.capitalize() == "False"):
            verified = False
        user = User.query.filter_by(email = email).first()
        if user:
            error = "Email already exists."
        elif not re.fullmatch(regex, email):
            error = "Email must be valid."
        elif len(first_name) < 1 or is_not_alpha(first_name):
            error = "Invalid name format selected."
        elif password1 != password2:
            error = "Passwords don\'t match."
        elif len(password1) < 8:
            error = "Password must be at least 8 characters."
        elif verified is not None and not verified:
            error = "Incorrect Captcha. Try Again"
        else:
            new_user = User(email = email, first_name = first_name, password = generate_password_hash(password1, method = 'sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember = True)
            flash('Account created!', category = 'success')
            return redirect(url_for('auth.otp', curr_user = email))
    return render_template("sign_up.html", user = current_user, error = error)