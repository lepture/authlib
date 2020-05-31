from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey, Ed25519PrivateKey
)
from cryptography.hazmat.primitives.asymmetric.ed448 import (
    Ed448PublicKey, Ed448PrivateKey
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PublicKey, X25519PrivateKey
)
from cryptography.hazmat.primitives.asymmetric.x448 import (
    X448PublicKey, X448PrivateKey
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)
from authlib.common.encoding import (
    to_unicode, to_bytes,
    urlsafe_b64decode, urlsafe_b64encode,
)
from authlib.jose.rfc7517 import Key
from ..rfc7518 import import_key, export_key


PUBLIC_KEYS_MAP = {
    'Ed25519': Ed25519PublicKey,
    'Ed448': Ed448PublicKey,
    'X25519': X25519PublicKey,
    'X448': X448PublicKey,
}
PRIVATE_KEYS_MAP = {
    'Ed25519': Ed25519PrivateKey,
    'Ed448': Ed448PrivateKey,
    'X25519': X25519PrivateKey,
    'X448': X448PrivateKey,
}
PUBLIC_KEY_TUPLE = tuple(PUBLIC_KEYS_MAP.values())
PRIVATE_KEY_TUPLE = tuple(PRIVATE_KEYS_MAP.values())


class OKPKey(Key):
    """Key class of the ``OKP`` key type."""

    kty = 'OKP'
    REQUIRED_JSON_FIELDS = ['crv', 'x']
    RAW_KEY_CLS = (
        Ed25519PublicKey, Ed25519PrivateKey,
        Ed448PublicKey, Ed448PrivateKey,
        X25519PublicKey, X25519PrivateKey,
        X448PublicKey, X448PrivateKey,
    )

    def as_pem(self, is_private=False, password=None):
        """Export key into PEM format bytes.

        :param is_private: export private key or public key
        :param password: encrypt private key with password
        :return: bytes
        """
        return export_key(self, is_private=is_private, password=password)

    def exchange_shared_key(self, pubkey):
        # used in ECDHAlgorithm
        if isinstance(self.raw_key, (X25519PrivateKey, X448PrivateKey)):
            return self.raw_key.exchange(pubkey)
        raise ValueError('Invalid key for exchanging shared key')

    @property
    def curve_key_size(self):
        raise NotImplementedError()

    @staticmethod
    def get_key_curve(key):
        if isinstance(key, (Ed25519PublicKey, Ed25519PrivateKey)):
            return 'Ed25519'
        elif isinstance(key, (Ed448PublicKey, Ed448PrivateKey)):
            return 'Ed448'
        elif isinstance(key, (X25519PublicKey, X25519PrivateKey)):
            return 'X25519'
        elif isinstance(key, (X448PublicKey, X448PrivateKey)):
            return 'X448'

    @staticmethod
    def loads_private_key(obj):
        crv_key = PRIVATE_KEYS_MAP[obj['crv']]
        d_bytes = urlsafe_b64decode(to_bytes(obj['d']))
        return crv_key.from_private_bytes(d_bytes)

    @staticmethod
    def loads_public_key(obj):
        crv_key = PUBLIC_KEYS_MAP[obj['crv']]
        x_bytes = urlsafe_b64decode(to_bytes(obj['x']))
        return crv_key.from_public_bytes(x_bytes)

    @staticmethod
    def dumps_private_key(raw_key):
        obj = OKPKey.dumps_public_key(raw_key.public_key())
        d_bytes = raw_key.private_bytes(
            Encoding.Raw,
            PrivateFormat.Raw,
            NoEncryption()
        )
        obj['d'] = to_unicode(urlsafe_b64encode(d_bytes))
        return obj

    @staticmethod
    def dumps_public_key(raw_key):
        x_bytes = raw_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return {
            'crv': OKPKey.get_key_curve(raw_key),
            'x': to_unicode(urlsafe_b64encode(x_bytes)),
        }

    @classmethod
    def import_key(cls, raw, options=None):
        """Import a key from PEM or dict data."""
        return import_key(
            cls, raw,
            PUBLIC_KEY_TUPLE, PRIVATE_KEY_TUPLE,
            b'ssh-ed25519', options
        )

    @classmethod
    def generate_key(cls, crv='Ed25519', options=None, is_private=False):
        if crv not in PRIVATE_KEYS_MAP:
            raise ValueError('Invalid crv value: "{}"'.format(crv))
        private_key_cls = PRIVATE_KEYS_MAP[crv]
        raw_key = private_key_cls.generate()
        if not is_private:
            raw_key = raw_key.public_key()
        return cls.import_key(raw_key, options=options)
