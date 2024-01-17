#!/usr/bin/env python3
''' Basic authentication module
'''
from api.v1.auth.auth import Auth
from base64 import b64decode


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
