import json
import datetime
import calendar
from authlib.specs.rfc7515 import JWS
from authlib.common.encoding import to_unicode
from .claims import JWTClaims


class JWT(JWS):
    claims_cls = JWTClaims

    def __init__(self, algorithms, load_key=None, claim_options=None):
        super(JWT, self).__init__(algorithms, load_key)
        self._claim_options = claim_options

    def encode(self, header, payload, key):
        header['typ'] = 'JWT'

        for k in ['exp', 'iat', 'nbf']:
            # convert datetime into timestamp
            claim = payload.get(k)
            if isinstance(claim, datetime.datetime):
                payload[k] = calendar.timegm(claim.utctimetuple())

        return super(JWT, self).encode(header, payload, key)

    def decode(self, s, key):
        header, bytes_payload = super(JWT, self).decode(s, key)
        payload = json.loads(to_unicode(bytes_payload))
        return self.claims_cls(payload, header, self._claim_options)
