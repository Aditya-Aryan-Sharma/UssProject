import json
import re
from flask import Blueprint, render_template, request, flash, jsonify, redirect, url_for, session
from flask_login import login_required, current_user
from .models import Note
from .models import User
from . import db
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

views = Blueprint('views', __name__)
regex = ("((http|https)://)(www.)?" + "[a-zA-Z0-9@:%._\\+~#?&//=]" + "{2,256}\\.[a-z]" + "{2,6}\\b([-a-zA-Z0-9@:%" + "._\\+~#?&//=]*)")

@views.route('/support', methods = ['GET'])
def support():
    return render_template('support.html', user = current_user)

@views.route('/profile', methods = ['GET', 'POST'])
@login_required
def profile():
    return render_template('profile.html', user = current_user)

@views.route('/', methods=['GET', 'POST'])
@login_required
def home():
    error = None
    encrypted_key = session.get("encrypted_key")
    cipher = AES.new(session.get("my_key"), AES.MODE_CBC, session.get("iv"))
    key = cipher.decrypt(encrypted_key)
    if len(key) > 8:
        key = key[:16]
    elif len(key) < 8:
        key = key + b'\x00'*(16 - len(key))
    if request.method == 'POST':
        my_key = AES.new(key, AES.MODE_CBC, key)
        comp = re.compile(regex)
        url = request.form.get('url')
        password = my_key.encrypt(pad((request.form.get('password')).encode(), AES.block_size))
        if url is None or not re.search(comp, url):
            error = "URL is invalid."
        elif len(password) < 1:
            error = "Password is not allowed to be null"
        else:
            new_cred = Note(url = url, domain_name = re.findall('://([\w\-\.]+)', url.strip(".com").strip(".in"))[0], encrypted_password = password, user_id = current_user.id)
            db.session.add(new_cred)
            db.session.commit()
            flash('Credentials added!', category = 'success')
    user_key = AES.new(key, AES.MODE_CBC, key)
    notes = Note.query.filter(User.id.in_([current_user.id])).all()
    List = []
    for note in notes:
        try:
            List.append((note.domain_name, unpad(user_key.decrypt(base64.b64decode(note.encrypted_password)), AES.block_size).decode(), note.url, note.id))
        except:
            List.append((note.domain_name, note.encrypted_password, note.url, note.id))
    return render_template("home.html", user = current_user, error = error, passwords = List)

@login_required
@views.route('/delete-note', methods=['POST'])
def delete_note():  
    note = json.loads(request.data)
    noteId = note['noteId']
    note = Note.query.get(noteId)
    if note:
        if note.user_id == current_user.id:
            db.session.delete(note)
            db.session.commit()

    return jsonify({})

@login_required
@views.route("/deleteAll", methods =['GET', 'POST'])
def deleteAll():
    note = Note.query.filter(User.id.in_([current_user.id])).all()
    for userNotes in note:
        db.session.delete(userNotes)
    db.session.commit()
    return redirect(url_for('views.home'))