# -*- coding: utf-8 -*-
"""
    authlib.jose.rfc7518
    ~~~~~~~~~~~~~~~~~~~~

    Cryptographic Algorithms for Keys per `Section 6`_.

    .. _`Section 6`: https://tools.ietf.org/html/rfc7518#section-6
"""
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateNumbers, RSAPublicNumbers,
    rsa_recover_prime_factors, rsa_crt_dmp1, rsa_crt_dmq1, rsa_crt_iqmp
)
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateNumbers, EllipticCurvePublicNumbers,
    SECP256R1, SECP384R1, SECP521R1,
)
from cryptography.hazmat.backends import default_backend
from authlib.common.encoding import base64_to_int, int_to_base64
from authlib.jose.rfc7517 import JWKAlgorithm
from ._key_cryptography import RSAKey, ECKey


class RSAAlgorithm(JWKAlgorithm):
    name = 'RSA'
    key_cls = RSAKey

    def loads_other_primes_info(self, key):
        raise NotImplementedError()

    def prepare_key(self, raw_data, **params):
        key = self.key_cls.from_raw(raw_data, **params)
        return key

    def loads_private_key(self, obj):
        if 'oth' in obj:  # pragma: no cover
            # https://tools.ietf.org/html/rfc7518#section-6.3.2.7
            return self.loads_other_primes_info(obj)

        props = ['p', 'q', 'dp', 'dq', 'qi']
        props_found = [prop in obj for prop in props]
        any_props_found = any(props_found)

        if any_props_found and not all(props_found):
            raise ValueError(
                'RSA key must include all parameters '
                'if any are present besides d')

        public_numbers = RSAPublicNumbers(
            base64_to_int(obj['e']), base64_to_int(obj['n']))

        if any_props_found:
            numbers = RSAPrivateNumbers(
                d=base64_to_int(obj['d']),
                p=base64_to_int(obj['p']),
                q=base64_to_int(obj['q']),
                dmp1=base64_to_int(obj['dp']),
                dmq1=base64_to_int(obj['dq']),
                iqmp=base64_to_int(obj['qi']),
                public_numbers=public_numbers)
        else:
            d = base64_to_int(obj['d'])
            p, q = rsa_recover_prime_factors(
                public_numbers.n, d, public_numbers.e)
            numbers = RSAPrivateNumbers(
                d=d,
                p=p,
                q=q,
                dmp1=rsa_crt_dmp1(d, p),
                dmq1=rsa_crt_dmq1(d, q),
                iqmp=rsa_crt_iqmp(p, q),
                public_numbers=public_numbers)

        return numbers.private_key(default_backend())

    def loads_public_key(self, obj):
        numbers = RSAPublicNumbers(
            base64_to_int(obj['e']),
            base64_to_int(obj['n'])
        )
        return numbers.public_key(default_backend())

    def loads(self, key):
        if key.key_data:
            return key

        if not key.dict_data:
            raise ValueError('Invalid key: %r'.format(key.raw_data))

        if 'd' in key.dict_data:
            key.key_data = self.loads_private_key(key.dict_data)
        else:
            key.key_data = self.loads_public_key(key.dict_data)
        return key

    def dumps_private_key(self, key_data):
        numbers = key_data.private_numbers()
        return {
            'n': int_to_base64(numbers.public_numbers.n),
            'e': int_to_base64(numbers.public_numbers.e),
            'd': int_to_base64(numbers.d),
            'p': int_to_base64(numbers.p),
            'q': int_to_base64(numbers.q),
            'dp': int_to_base64(numbers.dmp1),
            'dq': int_to_base64(numbers.dmq1),
            'qi': int_to_base64(numbers.iqmp)
        }

    def dumps_public_key(self, key_data):
        numbers = key_data.public_numbers()
        return {
            'n': int_to_base64(numbers.n),
            'e': int_to_base64(numbers.e)
        }

    def dumps(self, key):
        if key.dict_data:
            return key

        private_key = key.private_key
        if private_key:
            key.dict_data = self.dumps_private_key(private_key)
        else:
            key.dict_data = self.dumps_public_key(key.public_key)
        return key


class ECAlgorithm(JWKAlgorithm):
    name = 'EC'
    key_cls = ECKey

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

    def prepare_key(self, raw_data, **params):
        key = self.key_cls.from_raw(raw_data, **params)
        return key

    def loads(self, key):
        if key.key_data:
            return key

        if not key.dict_data:
            raise ValueError('Invalid key: %r'.format(key.raw_data))

        obj = key.dict_data
        curve = self.DSS_CURVES[obj['crv']]()
        public_numbers = EllipticCurvePublicNumbers(
            base64_to_int(obj['x']),
            base64_to_int(obj['y']),
            curve,
        )
        if 'd' in key.dict_data:
            private_numbers = EllipticCurvePrivateNumbers(
                base64_to_int(obj['d']),
                public_numbers
            )
            key.key_data = private_numbers.private_key(default_backend())
        else:
            key.key_data = public_numbers.public_key(default_backend())
        return key

    def dumps_private_key(self, key_data):
        numbers = key_data.private_numbers()
        return {
            'kty': self.name,
            'crv': self.CURVES_DSS[key_data.curve.name],
            'x': int_to_base64(numbers.public_numbers.x),
            'y': int_to_base64(numbers.public_numbers.y),
            'd': int_to_base64(numbers.private_value),
        }

    def dumps_public_key(self, key_data):
        numbers = key_data.public_numbers()
        return {
            'kty': self.name,
            'crv': self.CURVES_DSS[numbers.curve.name],
            'x': int_to_base64(numbers.x),
            'y': int_to_base64(numbers.y)
        }

    def dumps(self, key):
        if key.dict_data:
            return key

        private_key = key.private_key
        if private_key:
            key.dict_data = self.dumps_private_key(private_key)
        else:
            key.dict_data = self.dumps_public_key(key.public_key)
        return key


rsa_alg = RSAAlgorithm()
ec_alg = ECAlgorithm()

JWK_ALGORITHMS = [rsa_alg, ec_alg]
