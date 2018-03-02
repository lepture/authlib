from authlib.specs.rfc7515 import JWS
from authlib.specs.rfc7517 import JWK
from authlib.specs.rfc7518 import JWS_ALGORITHMS, JWK_ALGORITHMS

jwk = JWK(algorithms=JWK_ALGORITHMS)


def load_key(key, header):
    if isinstance(key, (tuple, list, dict)):
        return jwk.loads(key, header.get('kid'))
    return key


jws = JWS(algorithms=JWS_ALGORITHMS, load_key=load_key)
