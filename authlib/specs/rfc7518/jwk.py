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
from cryptography.hazmat.backends import default_backend
from authlib.common.encoding import (
    to_bytes, to_unicode,
    urlsafe_b64encode, urlsafe_b64decode,
    base64_to_int, int_to_base64
)


class BaseAlgorithm(object):
    @staticmethod
    def loads(obj):
        raise NotImplementedError

    @staticmethod
    def dumps(s):
        raise NotImplementedError


class OCTAlgorithm(BaseAlgorithm):
    @staticmethod
    def loads(obj):
        return urlsafe_b64decode(to_bytes(obj['k']))

    @staticmethod
    def dumps(s):
        return json.dumps({
            'k': to_unicode(urlsafe_b64encode(to_bytes(s))),
            'kty': 'oct'
        })


class RSAAlgorithm(BaseAlgorithm):
    @staticmethod
    def loads_other_primes_info(obj):
        raise NotImplementedError()

    @staticmethod
    def loads_private_key(obj):
        if 'oth' in obj:
            # https://tools.ietf.org/html/rfc7518#section-6.3.2.7
            return RSAAlgorithm.loads_other_primes_info(obj)

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

    @staticmethod
    def loads_public_key(obj):
        numbers = RSAPublicNumbers(
            base64_to_int(obj['e']), base64_to_int(obj['n'])
        )
        return numbers.public_key(default_backend())

    @staticmethod
    def loads(obj):
        if 'd' in obj and 'e' in obj and 'n' in obj:
            return RSAAlgorithm.loads_private_key(obj)
        elif 'n' in obj and 'e' in obj:
            return RSAAlgorithm.loads_public_key(obj)
        else:
            raise ValueError('Not a public or private key')

    @staticmethod
    def dumps_private_key(key):
        numbers = key.private_numbers()
        return {
            'kty': 'RSA',
            'key_ops': ['sign'],
            'n': to_unicode(int_to_base64(numbers.public_numbers.n)),
            'e': to_unicode(int_to_base64(numbers.public_numbers.e)),
            'd': to_unicode(int_to_base64(numbers.d)),
            'p': to_unicode(int_to_base64(numbers.p)),
            'q': to_unicode(int_to_base64(numbers.q)),
            'dp': to_unicode(int_to_base64(numbers.dmp1)),
            'dq': to_unicode(int_to_base64(numbers.dmq1)),
            'qi': to_unicode(int_to_base64(numbers.iqmp))
        }

    @staticmethod
    def dumps_public_key(key):
        numbers = key.public_numbers()
        return {
            'kty': 'RSA',
            'key_ops': ['verify'],
            'n': to_unicode(int_to_base64(numbers.n)),
            'e': to_unicode(int_to_base64(numbers.e))
        }

    @staticmethod
    def dumps(key):
        if getattr(key, 'private_numbers', None):
            return RSAAlgorithm.dumps_private_key(key)
        elif getattr(key, 'verify', None):
            return RSAAlgorithm.dumps_public_key(key)
        else:
            raise ValueError('Not a public or private key')


class ECAlgorithm(BaseAlgorithm):
    @staticmethod
    def loads(obj):
        raise NotImplementedError

    @staticmethod
    def dumps(s):
        raise NotImplementedError


JWK_ALGORITHMS = {
    'oct': OCTAlgorithm,
    'RSA': RSAAlgorithm,
    'EC': ECAlgorithm
}
