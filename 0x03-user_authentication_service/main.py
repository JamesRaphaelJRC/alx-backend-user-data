#!/usr/bin/env python3
''' End-to-end integration Test '''
import requests


URL = "http://127.0.0.1:5000"
EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"


def register_user(email: str, password: str) -> None:
    ''' Test user registration '''
    data = {
        "email": email,
        "password": password
    }
    response = requests.post(f'{URL}/users', data=data)

    expected_message = {'email': email, 'message': 'user created'}

    assert response.status_code == 200
    assert response.json() == expected_message


def log_in_wrong_password(email: str, password: str) -> None:
    ''' Test login with wrong credentials '''
    credentials = {
        "email": email,
        "password": password
    }

    response = requests.post(f"{URL}/sessions", data=credentials)

    assert response.status_code == 401


def log_in(email: str, password: str) -> str:
    ''' Test user login '''
    credentials = {
        "email": email,
        "password": password
    }

    response = requests.post(f"{URL}/sessions", data=credentials)
    expected_message = {"email": email, "message": "logged in"}

    assert response.status_code == 200
    assert response.json() == expected_message

    session_id = response.cookies.get("session_id")

    return session_id


def profile_unlogged() -> None:
    """ Test for validating request to /profile without loging in """
    cookies = {
        "session_id": ""
    }
    response = requests.get(f'{URL}/profile', cookies=cookies)

    assert response.status_code == 403


def profile_logged(session_id: str) -> None:
    ''' Test for validating request to /profile with valid session_id '''
    cookies = {"session_id": session_id}

    response = requests.get(f"{URL}/profile", cookies=cookies)

    assert response.status_code == 200
    assert response.json() == {"email": EMAIL}


def log_out(session_id: str) -> None:
    ''' Test for validating DELETE request to /sessions route '''
    cookies = {"session_id": session_id}

    response = requests.delete(f"{URL}/sessions", cookies=cookies)

    expected_message = {"message": "Bienvenue"}

    assert response.status_code == 200
    assert response.json() == expected_message


def reset_password_token(email: str) -> str:
    ''' Test for validating POST request to /reset_password route '''
    credentials = {"email": email}

    response = requests.post(f"{URL}/reset_password", data=credentials)
    reset_token = response.json().get('reset_token')

    expected_message = {"email": EMAIL, "reset_token": reset_token}

    assert response.status_code == 200
    assert response.json() == expected_message

    return reset_token


def update_password(email: str, reset_token: str, new_password: str) -> None:
    ''' Test for validating PUT request to the /reset_password route '''
    credentials = {
        "email": email,
        "reset_token": reset_token,
        "new_password": new_password
    }

    response = requests.put(f"{URL}/reset_password", data=credentials)

    expected_message = {"email": EMAIL, "message": "Password updated"}

    assert response.status_code == 200
    assert response.json() == expected_message


if __name__ == "__main__":
    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
