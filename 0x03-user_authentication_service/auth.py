#!/usr/bin/env python3
''' Authentication Module '''
import bcrypt


def _hash_password(password: str) -> bytes:
    ''' Returns the salted hash of a given password
    '''
    password = password.encode('utf-8')
    return bcrypt.hashpw(password, bcrypt.gensalt())
