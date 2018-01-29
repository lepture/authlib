import os

ROOT = os.path.abspath(os.path.dirname(__file__))


def get_rsa_private_key():
    return _read_file('rsa_private.pem')


def get_rsa_public_key():
    return _read_file('rsa_public.pem')


def _read_file(name):
    with open(os.path.join(ROOT, name), 'r') as f:
        return f.read()
