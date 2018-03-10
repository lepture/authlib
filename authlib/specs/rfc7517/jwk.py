from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey, EllipticCurvePublicKey
)
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey, RSAPublicKey
)

EC_TYPES = (EllipticCurvePrivateKey, EllipticCurvePublicKey)
RSA_TYPES = (RSAPrivateKey, RSAPublicKey)


class JWKAlgorithm(object):
    """Interface for JWK algorithm. JWA specification (RFC7518) SHOULD
    implement the algorithms for JWK with this base implementation.
    """
    def loads(self, obj):
        """Load JWK dict object into a public/private key."""
        raise NotImplementedError

    def dumps(self, key):
        """Dump a public/private key into JWK dict object."""
        raise NotImplementedError


class JWK(object):
    def __init__(self, algorithms):
        self._algorithms = algorithms

    def _loads(self, obj):
        kty = obj['kty']
        alg = self._algorithms[kty]
        return alg.loads(obj)

    def loads(self, obj, kid=None):
        """Loads JSON Web Key object into a public/private key.

        :param obj: A JWK (or JWK set) format dict
        :param kid: kid of a JWK set
        :return: key
        """
        if 'kty' in obj:
            if kid and 'kid' in obj and kid != obj['kid']:
                raise ValueError('Invalid JSON Web Key')
            return self._loads(obj)
        if not kid:
            raise ValueError('Invalid JSON Web Key')

        if isinstance(obj, (tuple, list)):
            keys = obj
        elif 'keys' in obj:
            keys = obj['keys']
        else:
            raise ValueError('Invalid JWK set format')

        for key in keys:
            if key['kid'] == kid:
                return self._loads(key)

    def dumps(self, key, kty=None, **params):
        """Generate JWK format for the given public/private key.

        :param key: A public/private key
        :param kty: Optional key type
        :param params: Other parameters
        :return: JWK dict
        """
        if kty is None:
            if isinstance(key, EC_TYPES):
                kty = 'EC'
            elif isinstance(key, RSA_TYPES):
                kty = 'RSA'
            else:
                kty = 'oct'
        alg = self._algorithms[kty]
        obj = alg.dumps(key)

        if params:
            # https://tools.ietf.org/html/rfc7517#section-4
            others = [
                'use', 'key_ops', 'alg', 'kid',
                'x5u', 'x5c', 'x5t', 'x5t#S256'
            ]
            for k in others:
                value = params.get(k)
                if value:
                    obj[k] = value
        return obj
