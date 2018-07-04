import re
import datetime
import calendar
from authlib.specs.rfc7515 import JWS
from authlib.specs.rfc7518 import JWS_ALGORITHMS
from authlib.common.encoding import text_types
from .errors import InsecureClaimError
from .claims import JWTClaims
from .util import create_key_func, decode_payload


_AVAILABLE_ALGORITHMS = {
    alg.name: alg for alg in JWS_ALGORITHMS
}


class JWT(object):
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
            self._jws = JWS(JWS_ALGORITHMS, private_headers)
        else:
            self._jws = JWS(None, private_headers)

            if isinstance(algorithms, (tuple, list)):
                for algorithm in algorithms:
                    self.register_algorithm(algorithm)
            elif isinstance(algorithms, text_types):
                self.register_algorithm(algorithms)

    def register_algorithm(self, algorithm):
        if isinstance(algorithm, text_types):
            algorithm = _AVAILABLE_ALGORITHMS.get(algorithm)

        if algorithm.TYPE == 'JWS':
            self._jws.register_algorithm(algorithm)

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

        key_func = create_key_func(key)
        return self._jws.serialize_compact(header, payload, key_func)

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

        key_func = create_key_func(key)
        data = self._jws.deserialize_compact(s, key_func)
        payload = decode_payload(data['payload'])
        return claims_cls(
            payload, data['header'],
            options=claims_options,
            params=claims_params,
        )
