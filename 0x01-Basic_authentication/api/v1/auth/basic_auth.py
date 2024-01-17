#!/usr/bin/env python3
''' Basic authentication module
'''
from api.v1.auth.auth import Auth


class BasicAuth(Auth):
    ''' Defines the Basic authentication class BasicAuth
    '''
    def __init__(self) -> None:
        super().__init__()
