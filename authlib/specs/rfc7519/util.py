import json
from authlib.common.encoding import text_types, to_unicode
from authlib.specs.rfc7515.errors import DecodeError
from authlib.specs.rfc7517 import JWK
from authlib.specs.rfc7518 import JWK_ALGORITHMS

jwk = JWK(algorithms=JWK_ALGORITHMS)


def _load_jwk(key, header):
    if not key and 'jwk' in header:
        key = header['jwk']
    if isinstance(key, (tuple, list, dict)):
        return jwk.loads(key, header.get('kid'))
    if isinstance(key, text_types) and \
            key.startswith('{') and key.endswith('}'):
        return jwk.loads(json.loads(key), header.get('kid'))
    return key


def create_key_func(key):
    if callable(key):
        def key_func(header, payload):
            v = key(header, payload)
            return _load_jwk(v, header)
    else:
        def key_func(header, payload):
            return _load_jwk(key, header)
    return key_func


def decode_payload(bytes_payload):
    try:
        payload = json.loads(to_unicode(bytes_payload))
    except ValueError:
        raise DecodeError('Invalid payload value')
    if not isinstance(payload, dict):
        raise DecodeError('Invalid payload type')
    return payload
