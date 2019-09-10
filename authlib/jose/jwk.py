from authlib.common.encoding import text_types, json_loads
from .rfc7517 import JsonWebKey
from .rfc7518 import JWK_ALGORITHMS

jwk = JsonWebKey(algorithms=JWK_ALGORITHMS)


def _load_jwk(key, header):
    if not key and 'jwk' in header:
        key = header['jwk']
    if isinstance(key, (tuple, list, dict)):
        return jwk.loads(key, header.get('kid'))
    if isinstance(key, text_types) and \
            key.startswith('{') and key.endswith('}'):
        return jwk.loads(json_loads(key), header.get('kid'))
    return key


def load_key(key, header, payload):
    if callable(key):
        key = key(header, payload)
    return _load_jwk(key, header)


def create_key_func(key):
    def key_func(header, payload):
        return load_key(key, header, payload)
    return key_func
