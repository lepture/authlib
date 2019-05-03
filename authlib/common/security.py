import os
import string
import secrets

UNICODE_ASCII_CHARACTER_SET = string.ascii_letters + string.digits


def generate_token(length=30, chars=UNICODE_ASCII_CHARACTER_SET):
    rand = secrets.SystemRandom()
    return ''.join(rand.choice(chars) for _ in range(length))


def is_secure_transport(uri):
    """Check if the uri is over ssl."""
    if os.getenv('AUTHLIB_INSECURE_TRANSPORT'):
        return True
    return uri.lower().startswith('https://')
