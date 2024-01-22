#!/usr/bin/env python3
"""
Module for handling Personal Data
"""
from typing import List
import re
import logging
from os import environ
# import mysql.connector


PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str) -> str:
    """ Returns a log message obfuscated """
    for data in fields:
        message = re.sub(f'{data}=.*?{separator}',
                         f'{data}={redaction}{separator}', message)
    return message
