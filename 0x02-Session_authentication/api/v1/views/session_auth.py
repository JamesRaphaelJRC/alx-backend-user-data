#!/usr/bin/env python3
''' Session views module
'''
from flask import request, jsonify, abort
from os import getenv
from api.v1.views import app_views
from models.user import User


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=True)
def login_user():
    ''' POST /api/v1/auth_session/login
    '''
    email = request.form.get('email', None)
    if email is None:
        return jsonify({"error": "email missing"}), 400

    password = request.form.get('password', None)
    if password is None:
        return jsonify({"error": "password missing"}), 400

    user = User.search({'email': email})
    if len(user) == 0:
        return jsonify({"error": "no user found for this email"}), 404

    user = user[0]

    if not user.is_valid_password(password):
        return jsonify({"error": "wrong password"}), 401

    from api.v1.app import auth

    # Creates  a session
    session_id = auth.create_session(user.id)

    # Jsonify returns a response object
    resp = jsonify(user.to_json())

    # Sets the cookie to the response object
    cookie_name = getenv('SESSION_NAME')
    resp.set_cookie(cookie_name, session_id)

    return resp


@app_views.route('/auth_session/logout',
                 methods=['DELETE'], strict_slashes=False)
def logout():
    """ DELETE /auth_session/logout
    Return:
        - Empty dictionary if succesful
    """
    from api.v1.app import auth

    was_deleted = auth.destroy_session(request)

    if not was_deleted:
        abort(404)

    return jsonify({}), 200
