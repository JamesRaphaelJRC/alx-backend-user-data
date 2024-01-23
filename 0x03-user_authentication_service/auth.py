#!/usr/bin/env python3
''' Authentication Module '''
from sqlalchemy.orm.exc import NoResultFound
import bcrypt
from db import DB
from user import User


class Auth:
    """Auth class to interact with the authentication database.
    """
    def __init__(self):
        self._db = DB()

    def _hash_password(self, password: str) -> bytes:
        ''' Returns the salted hash of a given password
        '''
        password = password.encode('utf-8')
        return bcrypt.hashpw(password, bcrypt.gensalt())

    def register_user(self, email, password):
        ''' Registers a new user by saving the user to the database
        '''
        try:
            user = self._db.find_user_by(email=email)
            if user:
                raise ValueError(f'User {email} already exists')
        except NoResultFound:
            hashed_password = self._hash_password(password)
            user = self._db.add_user(email, hashed_password)
            return user
