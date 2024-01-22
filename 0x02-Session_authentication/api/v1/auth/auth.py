#!/usr/bin/env python3
''' Module for API authentication
'''
from typing import List, TypeVar
from flask import request
from os import getenv


class Auth:
    ''' The API authentication class
    '''
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        ''' Verifies if a path will require authentication.
        Args:
            path - The path to be verified
            excluded_paths - a list of paths that do not require authentication
        Assumptions:
            excluded_paths contains string path always ending by a /
            this method is slash tolerant path=/api/v1/status
                and path=/api/v1/status/ must be returned False if
                excluded_paths contains /api/v1/status/
        Return:
            False if path is in excluded_paths
            True if path is not in excluded_paths (i.e. path requires auth)
            True if path is None
            True if excluded_paths is None or empty
        '''
        if path is None or excluded_paths is None or len(excluded_paths) == 0:
            return True

        path = path.rstrip('/')  # Removes all '/' from path before comparison

        for excluded_path in excluded_paths:
            # Remove all '/' from excluded_path before comparison with path
            excluded_path = excluded_path.rstrip('/')

            if excluded_path.endswith('*'):
                if path.startswith(excluded_path[:-1]):  # Excludes '*'
                    return False
            elif path == excluded_path:
                return False
        return True

    def authorization_header(self, request=None) -> str:
        ''' Verifies if the request object contains the authorization header
        args:
            request - A flask request object.
        Return:
            Value of the request header 'Authorization' if
            'Authorization' is in the request object and None otherwise
        '''
        if request is None or 'Authorization' not in request.headers:
            return None
        return request.headers['Authorization']

    def current_user(self, request=None) -> TypeVar('User'):
        ''' Returns None
        '''
        return None

    def session_cookie(self, request=None):
        ''' Returns a cookie value from a request
        '''
        if request is None:
            return None

        cookie_name = getenv('SESSION_NAME')
        return request.cookies.get(cookie_name)
