#!/usr/bin/env python3
"""
Encrypting passwords using bcrypt.
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hashes a password using bcrypt and returns the salted,
    hashed password as a byte string.

    Args:
        password (str): The plain text password to be hashed.

    Returns:
        bytes: The salted, hashed password.
    """
    encoded_password = password.encode()
    hashed_password = bcrypt.hashpw(encoded_password, bcrypt.gensalt())

    return hashed_password


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Validates that a given password matches the stored hashed password.

    Args:
        hashed_password (bytes): The hashed password to compare against.
        password (str): The plain text password to validate.

    Returns:
        bool: True if password match hashed password, else False.
    """
    encoded_password = password.encode()
    return bcrypt.checkpw(encoded_password, hashed_password)
