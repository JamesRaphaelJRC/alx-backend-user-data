#!/usr/bin/env python3
''' Flask app '''
from flask import Flask, jsonify, request, abort, session, redirect, url_for
from auth import Auth

app = Flask(__name__)
app.url_map.strict_slashes = False
AUTH = Auth()


@app.route("/")
def index():
    ''' GET /
    Index page
    '''
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"])
def create_new_user():
    ''' POST /users
    Creates a new user using an email and password
    '''
    email = request.form.get('email')
    password = request.form.get('password')

    try:
        AUTH.register_user(email, password)
        return jsonify({"email": f"{email}", "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route('/sessions', methods=['POST'])
def login():
    ''' POST /sessions
    Implements a login functionality and creates and stores a new session
    for the user
    '''
    email = request.form.get('email')
    password = request.form.get('password')

    if not AUTH.valid_login(email, password):
        abort(401)

    session_id = AUTH.create_session(email)
    message = {"email": email, "message": "logged in"}

    response = jsonify(message)
    response.set_cookie("session_id", session_id)

    return response


@app.route('/sessions', methods=['DELETE'])
def logout() -> str:
    ''' DELETE /sessions
    '''
    session_id = request.cookies.get('session_id')

    user = AUTH.get_user_from_session_id(session_id)

    if user is None:
        abort(403)

    AUTH.destroy_session(user.id)

    return redirect('/')


if __name__ == '__main__':
    app.run(host="0.0.0.0", port="5000")
