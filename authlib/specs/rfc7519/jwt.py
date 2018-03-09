import json
import datetime
import calendar
from authlib.specs.rfc7515 import JWS
from authlib.specs.rfc7517 import JWK
from authlib.specs.rfc7518 import JWS_ALGORITHMS, JWK_ALGORITHMS
from authlib.common.encoding import text_types, to_unicode
from .claims import JWTClaims


class JWT(JWS):
    def __init__(self, algorithms=None, load_key=None):
        if algorithms is None:
            algorithms = JWS_ALGORITHMS
        elif isinstance(algorithms, (tuple, list)):
            algorithms = {k: JWS_ALGORITHMS[k] for k in algorithms}
        elif isinstance(algorithms, text_types):
            algorithms = {algorithms: JWS_ALGORITHMS[algorithms]}
        if load_key is None:
            load_key = _load_jwk
        super(JWT, self).__init__(algorithms, load_key)

    def encode(self, header, payload, key):
        header['typ'] = 'JWT'

        for k in ['exp', 'iat', 'nbf']:
            # convert datetime into timestamp
            claim = payload.get(k)
            if isinstance(claim, datetime.datetime):
                payload[k] = calendar.timegm(claim.utctimetuple())

        return super(JWT, self).encode(header, payload, key)

    def decode(self, s, key, claims_cls=None, claims_options=None, claims_request=None):
        if claims_cls is None:
            claims_cls = JWTClaims
        header, bytes_payload = super(JWT, self).decode(s, key)
        payload = json.loads(to_unicode(bytes_payload))
        return claims_cls(
            payload, header,
            options=claims_options,
            request=claims_request,
        )


jwk = JWK(algorithms=JWK_ALGORITHMS)


def _load_jwk(key, header):
    if not key and 'jwk' in header:
        key = header['jwk']
    if isinstance(key, (tuple, list, dict)):
        return jwk.loads(key, header.get('kid'))
    if isinstance(key, text_types) and key.startswith('{'):
        return jwk.loads(json.loads(key), header.get('kid'))
    return key
