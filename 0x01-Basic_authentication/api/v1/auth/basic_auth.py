#!/usr/bin/env python3
''' Basic authentication module
'''
from api.v1.auth.auth import Auth
from base64 import b64decode
from typing import TypeVar


class BasicAuth(Auth):
    ''' Defines the Basic authentication class BasicAuth
    '''
    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        ''' Extracts the Base64 part of the Authorization header
        '''
        if authorization_header is None or type(
            authorization_header) != str or not authorization_header.\
                startswith('Basic '):
            return None
        return authorization_header[6:]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        ''' Decodes and returns the decoded value of a Base64 string
        '''
        if base64_authorization_header is None or\
                type(base64_authorization_header) != str:
            return None
        try:
            encoded = base64_authorization_header.encode('utf-8')
            decoded64 = b64decode(encoded)
            decoded = decoded64.decode('utf-8')
        except BaseException:
            return None
        return decoded

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> (str, str):
        ''' Returns the user email and password from the Base64
        decoded value
        '''
        if decoded_base64_authorization_header is None or\
                type(decoded_base64_authorization_header) != str or\
                ':' not in decoded_base64_authorization_header:
            return None, None
        email, password = decoded_base64_authorization_header.split(':')
        return email, password

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        ''' Returns the User instance based on email and password
        and returns None if there is no User instance with given user_email or
        user_pwd is invalid
        '''
        if user_email is None or user_pwd is None:
            return None
        if type(user_email) != str or type(user_pwd) != str:
            return None
        from models.user import User

        User.load_from_file()
        from models.base import DATA
        if len(DATA) == 0:
            return None
        users = DATA.get('User')

        # Check if a User instance with email == user_email exists
        user_instance = [user for user in users.values() if user.search(
            {'email': user_email}) != [] and user.is_valid_password(user_pwd)]

        # Check if no instance is found
        if len(user_instance) == 0:
            return None
        else:
            return user_instance[0]
