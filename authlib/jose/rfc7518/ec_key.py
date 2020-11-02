from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePublicKey, EllipticCurvePrivateKeyWithSerialization,
    EllipticCurvePrivateNumbers, EllipticCurvePublicNumbers,
    SECP256R1, SECP384R1, SECP521R1, SECP256K1,
)
from cryptography.hazmat.backends import default_backend
from authlib.common.encoding import base64_to_int, int_to_base64
from .key_util import export_key, import_key
from ..rfc7517 import Key


class ECKey(Key):
    """Key class of the ``EC`` key type."""

    kty = 'EC'
    DSS_CURVES = {
        'P-256': SECP256R1,
        'P-384': SECP384R1,
        'P-521': SECP521R1,
        # https://tools.ietf.org/html/rfc8812#section-3.1
        'secp256k1': SECP256K1,
    }
    CURVES_DSS = {
        SECP256R1.name: 'P-256',
        SECP384R1.name: 'P-384',
        SECP521R1.name: 'P-521',
        SECP256K1.name: 'secp256k1',
    }
    REQUIRED_JSON_FIELDS = ['crv', 'x', 'y']
    RAW_KEY_CLS = (EllipticCurvePublicKey, EllipticCurvePrivateKeyWithSerialization)

    def as_pem(self, is_private=False, password=None):
        """Export key into PEM format bytes.

        :param is_private: export private key or public key
        :param password: encrypt private key with password
        :return: bytes
        """
        return export_key(self, is_private=is_private, password=password)

    def exchange_shared_key(self, pubkey):
        # # used in ECDHAlgorithm
        if isinstance(self.raw_key, EllipticCurvePrivateKeyWithSerialization):
            return self.raw_key.exchange(ec.ECDH(), pubkey)
        raise ValueError('Invalid key for exchanging shared key')

    @property
    def curve_name(self):
        return self.CURVES_DSS[self.raw_key.curve.name]

    @property
    def curve_key_size(self):
        return self.raw_key.curve.key_size

    @classmethod
    def loads_private_key(cls, obj):
        curve = cls.DSS_CURVES[obj['crv']]()
        public_numbers = EllipticCurvePublicNumbers(
            base64_to_int(obj['x']),
            base64_to_int(obj['y']),
            curve,
        )
        private_numbers = EllipticCurvePrivateNumbers(
            base64_to_int(obj['d']),
            public_numbers
        )
        return private_numbers.private_key(default_backend())

    @classmethod
    def loads_public_key(cls, obj):
        curve = cls.DSS_CURVES[obj['crv']]()
        public_numbers = EllipticCurvePublicNumbers(
            base64_to_int(obj['x']),
            base64_to_int(obj['y']),
            curve,
        )
        return public_numbers.public_key(default_backend())

    @classmethod
    def dumps_private_key(cls, raw_key):
        numbers = raw_key.private_numbers()
        return {
            'crv': cls.CURVES_DSS[raw_key.curve.name],
            'x': int_to_base64(numbers.public_numbers.x),
            'y': int_to_base64(numbers.public_numbers.y),
            'd': int_to_base64(numbers.private_value),
        }

    @classmethod
    def dumps_public_key(cls, raw_key):
        numbers = raw_key.public_numbers()
        return {
            'crv': cls.CURVES_DSS[numbers.curve.name],
            'x': int_to_base64(numbers.x),
            'y': int_to_base64(numbers.y)
        }

    @classmethod
    def import_key(cls, raw, options=None) -> 'ECKey':
        """Import a key from PEM or dict data."""
        return import_key(
            cls, raw,
            EllipticCurvePublicKey, EllipticCurvePrivateKeyWithSerialization,
            b'ecdsa-sha2-', options
        )

    @classmethod
    def generate_key(cls, crv='P-256', options=None, is_private=False) -> 'ECKey':
        if crv not in cls.DSS_CURVES:
            raise ValueError('Invalid crv value: "{}"'.format(crv))
        raw_key = ec.generate_private_key(
            curve=cls.DSS_CURVES[crv](),
            backend=default_backend(),
        )
        if not is_private:
            raw_key = raw_key.public_key()
        return cls.import_key(raw_key, options=options)
