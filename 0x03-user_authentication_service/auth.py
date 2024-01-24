#!/usr/bin/env python3
''' Authentication Module '''
from sqlalchemy.orm.exc import NoResultFound
from uuid import uuid4
import bcrypt
from db import DB
from user import User


def _hash_password(password: str) -> bytes:
    ''' Returns the salted hash of a given password
    '''
    password = password.encode('utf-8')
    return bcrypt.hashpw(password, bcrypt.gensalt())


def _generate_uuid() -> str:
    ''' Generates and returns a unique UUID
    '''
    return str(uuid4())


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

    def create_session(self, email: str) -> str:
        ''' Generates a session_id for a given user
        Return:
            session_id - on success
            None - otherwise
        '''
        try:
            user = self._db.find_user_by(email=email)
            session_id = _generate_uuid()

            user.session_id = session_id
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> User:
        ''' Fetches a user from the database using the correct session_id
        '''
        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except NoResultFound:
            return None

    def destroy_session(self, user_id: str) -> None:
        ''' Updates a user's session_id to none
        '''
        self._db.update_user(user_id, session_id=None)
        return None

    def get_reset_password_token(self, email: str) -> str:
        ''' Generates a token that enables a user to reset password
        '''
        try:
            user = self._db.find_user_by(email=email)

            token = _generate_uuid()
            self._db.update_user(user.id, reset_token=token)
            return token
        except NoResultFound:
            raise ValueError

    def update_password(self, reset_token: str, password: str) -> str:
        ''' Updates a user's password
        '''
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            hashed_password = _hash_password(password)
            self._db.update_user(user.id, hashed_password=hashed_password,
                                 reset_token=None)
            return None
        except NoResultFound:
            raise ValueError
