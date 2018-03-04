# -*- coding: utf-8 -*-
"""
    authlib.specs.rfc7518.jws
    ~~~~~~~~~~~~~~~~~~~~~~~~~

    Cryptographic Algorithms for Keys per `Section 6`_.

    .. _`Section 6`: https://tools.ietf.org/html/rfc7518#section-6
"""

import json
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateNumbers, RSAPublicNumbers,
    rsa_recover_prime_factors, rsa_crt_dmp1, rsa_crt_dmq1, rsa_crt_iqmp
)
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateNumbers, EllipticCurvePublicNumbers,
    SECP256R1, SECP384R1, SECP521R1,
)
from cryptography.hazmat.backends import default_backend
from authlib.specs.rfc7517 import JWKAlgorithm
from authlib.common.encoding import (
    to_bytes, to_unicode,
    urlsafe_b64encode, urlsafe_b64decode,
    base64_to_int, int_to_base64
)


class OCTAlgorithm(JWKAlgorithm):
    def loads(self, obj):
        return urlsafe_b64decode(to_bytes(obj['k']))

    def dumps(self, s):
        return json.dumps({
            'k': to_unicode(urlsafe_b64encode(to_bytes(s))),
            'kty': 'oct'
        })


class RSAAlgorithm(JWKAlgorithm):
    def loads_other_primes_info(self, obj):
        raise NotImplementedError()

    def loads_private_key(self, obj):
        if 'oth' in obj:
            # https://tools.ietf.org/html/rfc7518#section-6.3.2.7
            return self.loads_other_primes_info(obj)

        props = ['p', 'q', 'dp', 'dq', 'qi']
        props_found = [prop in obj for prop in props]
        any_props_found = any(props_found)

        if any_props_found and not all(props_found):
            raise ValueError('RSA key must include all parameters if any are present besides d')

        public_numbers = RSAPublicNumbers(
            base64_to_int(obj['e']), base64_to_int(obj['n'])
        )

        if any_props_found:
            numbers = RSAPrivateNumbers(
                d=base64_to_int(obj['d']),
                p=base64_to_int(obj['p']),
                q=base64_to_int(obj['q']),
                dmp1=base64_to_int(obj['dp']),
                dmq1=base64_to_int(obj['dq']),
                iqmp=base64_to_int(obj['qi']),
                public_numbers=public_numbers
            )
        else:
            d = base64_to_int(obj['d'])
            p, q = rsa_recover_prime_factors(
                public_numbers.n, d, public_numbers.e
            )

            numbers = RSAPrivateNumbers(
                d=d,
                p=p,
                q=q,
                dmp1=rsa_crt_dmp1(d, p),
                dmq1=rsa_crt_dmq1(d, q),
                iqmp=rsa_crt_iqmp(p, q),
                public_numbers=public_numbers
            )

        return numbers.private_key(default_backend())

    def loads_public_key(self, obj):
        numbers = RSAPublicNumbers(
            base64_to_int(obj['e']), base64_to_int(obj['n'])
        )
        return numbers.public_key(default_backend())

    def loads(self, obj):
        if 'd' in obj and 'e' in obj and 'n' in obj:
            return self.loads_private_key(obj)
        elif 'n' in obj and 'e' in obj:
            return self.loads_public_key(obj)
        else:
            raise ValueError('Not a public or private key')

    def dumps_private_key(self, key):
        numbers = key.private_numbers()
        return {
            'kty': 'RSA',
            'n': to_unicode(int_to_base64(numbers.public_numbers.n)),
            'e': to_unicode(int_to_base64(numbers.public_numbers.e)),
            'd': to_unicode(int_to_base64(numbers.d)),
            'p': to_unicode(int_to_base64(numbers.p)),
            'q': to_unicode(int_to_base64(numbers.q)),
            'dp': to_unicode(int_to_base64(numbers.dmp1)),
            'dq': to_unicode(int_to_base64(numbers.dmq1)),
            'qi': to_unicode(int_to_base64(numbers.iqmp))
        }

    def dumps_public_key(self, key):
        numbers = key.public_numbers()
        return {
            'kty': 'RSA',
            'n': to_unicode(int_to_base64(numbers.n)),
            'e': to_unicode(int_to_base64(numbers.e))
        }

    def dumps(self, key):
        if getattr(key, 'private_numbers', None):
            return self.dumps_private_key(key)
        elif getattr(key, 'verify', None):
            return self.dumps_public_key(key)
        else:
            raise ValueError('Not a public or private key')


class ECAlgorithm(JWKAlgorithm):
    # http://tools.ietf.org/html/rfc4492#appendix-A
    # https://tools.ietf.org/html/rfc7518#section-6.2.1.1
    DSS_CURVES = {
        'P-256': SECP256R1,
        'P-384': SECP384R1,
        'P-521': SECP521R1,
    }
    CURVES_DSS = {
        SECP256R1.name: 'P-256',
        SECP384R1.name: 'P-384',
        SECP521R1.name: 'P-521',
    }

    @classmethod
    def register_curve(cls, name, curve):
        if name not in cls.DSS_CURVES:
            cls.DSS_CURVES[name] = curve
            cls.CURVES_DSS[curve.name] = name

    def loads(self, obj):
        for k in ['crv', 'x', 'y']:
            if k not in obj:
                raise ValueError('Not a elliptic curve key')

        curve = self.DSS_CURVES[obj['crv']]()
        public_numbers = EllipticCurvePublicNumbers(
            base64_to_int(obj['x']),
            base64_to_int(obj['y']),
            curve,
        )
        if 'd' in obj:
            private_numbers = EllipticCurvePrivateNumbers(
                base64_to_int(obj['d']),
                public_numbers
            )
            return private_numbers.private_key(default_backend())
        return public_numbers.public_key(default_backend())

    def dumps_private_key(self, key):
        numbers = key.private_numbers()

        return {
            'kty': 'EC',
            'crv': self.CURVES_DSS[numbers.curve.name],
            'x': to_unicode(int_to_base64(numbers.public_numbers.x)),
            'y': to_unicode(int_to_base64(numbers.public_numbers.y)),
            'd': to_unicode(int_to_base64(numbers.d)),
        }

    def dumps_public_key(self, key):
        numbers = key.public_numbers()
        return {
            'kty': 'EC',
            'crv': self.CURVES_DSS[numbers.curve.name],
            'x': to_unicode(int_to_base64(numbers.x)),
            'y': to_unicode(int_to_base64(numbers.y))
        }

    def dumps(self, key):
        if getattr(key, 'private_numbers', None):
            return self.dumps_private_key(key)
        elif getattr(key, 'verify', None):
            return self.dumps_public_key(key)
        else:
            raise ValueError('Not a elliptic curve key')


JWK_ALGORITHMS = {
    'oct': OCTAlgorithm(),
    'RSA': RSAAlgorithm(),
    'EC': ECAlgorithm(),
}
