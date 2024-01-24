#!/usr/bin/env python3
''' Flask app '''
from flask import Flask, jsonify, request
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


if __name__ == '__main__':
    app.run(host="0.0.0.0", port="5000")
