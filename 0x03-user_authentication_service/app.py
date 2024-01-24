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

    if session_id is None:
        abort(403)

    user = AUTH.get_user_from_session_id(session_id)

    if user is None:
        abort(403)

    AUTH.destroy_session(user.id)

    return redirect('/')


@app.route('/profile')
def profile() -> str:
    ''' GET /profile
    Return:
        User credentials
    '''
    session_id = request.cookies.get('session_id')
    if session_id is None:
        abort(403)

    user = AUTH.get_user_from_session_id(session_id)

    if user is None:
        abort(403)

    return jsonify({"email": user.email}), 200


@app.route('/reset_password', methods=['POST', 'PUT'])
def reset_password():
    ''' POST /reset_password
    Handles token generation for a user to reset password

    PUT /reset_password
    Updates the user password with the new password
    '''
    if request.method == 'POST':  # Handles reset_token generation
        email = request.form.get('email')
        if email is None:
            abort(403)

        try:
            token = AUTH.get_reset_password_token(email)
            return jsonify({"email": email, "reset_token": token})
        except ValueError:
            abort(403)

    if request.method == 'PUT':  # Handles new password update
        email = request.form.get('email')
        reset_token = request.form.get('reset_token')
        new_password = request.form.get('new_password')

        if email is None or reset_token is None or new_password is None:
            abort(403)

        try:
            AUTH.update_password(reset_token, new_password)
            return jsonify({"email": email, "message": "Password updated"})
        except ValueError:
            abort(403)


if __name__ == '__main__':
    app.run(host="0.0.0.0", port="5000")
