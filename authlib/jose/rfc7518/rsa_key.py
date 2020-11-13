from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPublicKey, RSAPrivateKeyWithSerialization,
    RSAPrivateNumbers, RSAPublicNumbers,
    rsa_recover_prime_factors, rsa_crt_dmp1, rsa_crt_dmq1, rsa_crt_iqmp
)
from cryptography.hazmat.backends import default_backend
from authlib.common.encoding import base64_to_int, int_to_base64
from .key_util import export_key, import_key
from ..rfc7517 import Key


class RSAKey(Key):
    """Key class of the ``RSA`` key type."""

    kty = 'RSA'
    RAW_KEY_CLS = (RSAPublicKey, RSAPrivateKeyWithSerialization)
    REQUIRED_JSON_FIELDS = ['e', 'n']

    def as_pem(self, is_private=False, password=None):
        """Export key into PEM format bytes.

        :param is_private: export private key or public key
        :param password: encrypt private key with password
        :return: bytes
        """
        return export_key(self, is_private=is_private, password=password)

    @staticmethod
    def dumps_private_key(raw_key):
        numbers = raw_key.private_numbers()
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

    @staticmethod
    def dumps_public_key(raw_key):
        numbers = raw_key.public_numbers()
        return {
            'n': int_to_base64(numbers.n),
            'e': int_to_base64(numbers.e)
        }

    @staticmethod
    def loads_private_key(obj):
        if 'oth' in obj:  # pragma: no cover
            # https://tools.ietf.org/html/rfc7518#section-6.3.2.7
            raise ValueError('"oth" is not supported yet')

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

    @staticmethod
    def loads_public_key(obj):
        numbers = RSAPublicNumbers(
            base64_to_int(obj['e']),
            base64_to_int(obj['n'])
        )
        return numbers.public_key(default_backend())

    @classmethod
    def import_key(cls, raw, options=None):
        """Import a key from PEM or dict data."""
        return import_key(
            cls, raw,
            RSAPublicKey, RSAPrivateKeyWithSerialization,
            b'ssh-rsa', options
        )

    @classmethod
    def generate_key(cls, key_size=2048, options=None, is_private=False):
        if key_size < 512:
            raise ValueError('key_size must not be less than 512')
        if key_size % 8 != 0:
            raise ValueError('Invalid key_size for RSAKey')
        raw_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend(),
        )
        if not is_private:
            raw_key = raw_key.public_key()
        return cls.import_key(raw_key, options=options)
