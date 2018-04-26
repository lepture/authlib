import re
import json
import datetime
import calendar
from authlib.specs.rfc7515 import JWS, DecodeError
from authlib.specs.rfc7517 import JWK
from authlib.specs.rfc7518 import JWS_ALGORITHMS, JWK_ALGORITHMS
from authlib.common.encoding import text_types, to_unicode
from .errors import InsecureClaimError
from .claims import JWTClaims


class JWT(JWS):
    SENSITIVE_NAMES = ('password', 'token', 'secret', 'secret_key')
    # Thanks to sentry SensitiveDataFilter
    SENSITIVE_VALUES = re.compile(r'|'.join([
        # http://www.richardsramblings.com/regex/credit-card-numbers/
        r'\b(?:3[47]\d|(?:4\d|5[1-5]|65)\d{2}|6011)\d{12}\b',
        # various private keys
        r'-----BEGIN[A-Z ]+PRIVATE KEY-----.+-----END[A-Z ]+PRIVATE KEY-----',
        # social security numbers (US)
        r'^\b(?!(000|666|9))\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b',
    ]), re.DOTALL)

    def __init__(self, algorithms=None, private_headers=None):
        if algorithms is None:
            algorithms = JWS_ALGORITHMS
        elif isinstance(algorithms, (tuple, list)):
            algorithms = {k: JWS_ALGORITHMS[k] for k in algorithms}
        elif isinstance(algorithms, text_types):
            algorithms = {algorithms: JWS_ALGORITHMS[algorithms]}
        super(JWT, self).__init__(algorithms, private_headers)

    def extract_payload(self, payload_segment):
        """Extract payload into JSON dict format."""
        bytes_payload = super(JWT, self).extract_payload(payload_segment)
        try:
            payload = json.loads(to_unicode(bytes_payload))
        except ValueError:
            raise DecodeError('Invalid payload value')
        if not isinstance(payload, dict):
            raise DecodeError('Invalid payload type')
        return payload

    def check_sensitive_data(self, payload):
        """Check if payload contains sensitive information."""
        for k in payload:
            # check claims key name
            if k in self.SENSITIVE_NAMES:
                raise InsecureClaimError(k)

            # check claims values
            v = payload[k]
            if isinstance(v, text_types) and self.SENSITIVE_VALUES.search(v):
                raise InsecureClaimError(k)

    def encode(self, header, payload, key, check=True):
        """Encode a JWT with the given header, payload and key.

        :param header: A dict of JWS header
        :param payload: A dict to be encoded
        :param key: key used to sign the signature
        :param check: check if sensitive data in payload
        :return: JWT
        """
        header['typ'] = 'JWT'

        for k in ['exp', 'iat', 'nbf']:
            # convert datetime into timestamp
            claim = payload.get(k)
            if isinstance(claim, datetime.datetime):
                payload[k] = calendar.timegm(claim.utctimetuple())

        if check:
            self.check_sensitive_data(payload)
        return self.serialize_compact(header, payload, _wrap_key(key))

    def decode(self, s, key, claims_cls=None,
               claims_options=None, claims_params=None):
        """Decode the JWS with the given key. This is similar with
        :meth:`verify`, except that it will raise BadSignatureError when
        signature doesn't match.

        :param s: text of JWT
        :param key: key used to verify the signature
        :param claims_cls: class to be used for JWT claims
        :param claims_options: `options` parameters for claims_cls
        :param claims_params: `params` parameters for claims_cls
        :return: claims_cls instance
        :raise: BadSignatureError
        """
        if claims_cls is None:
            claims_cls = JWTClaims

        data = self.deserialize_compact(s, _wrap_key(key))
        return claims_cls(
            data['payload'], data['header'],
            options=claims_options,
            params=claims_params,
        )


jwk = JWK(algorithms=JWK_ALGORITHMS)
jwt = JWT()


def _load_jwk(key, header):
    if not key and 'jwk' in header:
        key = header['jwk']
    if isinstance(key, (tuple, list, dict)):
        return jwk.loads(key, header.get('kid'))
    if isinstance(key, text_types) and \
            key.startswith('{') and key.endswith('}'):
        return jwk.loads(json.loads(key), header.get('kid'))
    return key


def _wrap_key(key):
    if callable(key):
        return key

    def key_func(header, payload):
        return _load_jwk(key, header)

    return key_func
