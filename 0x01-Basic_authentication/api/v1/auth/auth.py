#!/usr/bin/env python3
''' Module for API authentication
'''
from typing import List, TypeVar
from flask import request


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

        if path[-1] != '/':
            path += '/'
        if path in excluded_paths:
            return False
        return True

    def authorization_header(self, request=None) -> str:
        ''' returns None
        '''
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        ''' Returns None
        '''
        return None
