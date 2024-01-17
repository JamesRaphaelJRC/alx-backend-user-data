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
