#!/usr/bin/env python3
''' Authentication Module '''
from sqlalchemy.orm.exc import NoResultFound
import bcrypt
from db import DB
from user import User


def _hash_password(password: str) -> bytes:
    ''' Returns the salted hash of a given password
    '''
    password = password.encode('utf-8')
    return bcrypt.hashpw(password, bcrypt.gensalt())


class Auth:
    """Auth class to interact with the authentication database.
    """
    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        ''' Registers a new user by saving the user to the database
        '''
        try:
            user = self._db.find_user_by(email=email)
            if user:
                raise ValueError(f'User {email} already exists')
        except NoResultFound:
            hashed_password = _hash_password(password)
            user = self._db.add_user(email, hashed_password)
            return user

    def valid_login(self, email: str, password: str) -> bool:
        ''' Authenticates user login credentials
        Return:
            True if credentials are valid
            False otherwise
        '''
        try:
            user = self._db.find_user_by(email=email)
            # Converts password to a byte object before comparison
            password = password.encode("utf-8")
            if not bcrypt.checkpw(password, user.hashed_password):
                return False
            return True
        except NoResultFound:
            return False
