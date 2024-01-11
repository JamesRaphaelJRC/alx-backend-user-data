#!/usr/bin/env python3
''' Defines a function filter_datum '''
import re
from typing import List


def filter_datum(fields: List[str], redaction: str, message: str,
                 separator: str):
    '''
    Returns the log message obfuscated

    Arguments:
    fields: a list of strings representing all fields to obfuscate
    redaction: a string representing by what the field will be obfuscated
    message: a string representing the log line
    separator: a string representing by which character is separating all
                fields in the log line (message)
    '''
    for data in fields:
        message = re.sub(f'{data}=.*?{separator}',
                         f'{data}={redaction}{separator}', message)
    return message
