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
from ..rfc7518._backends import import_key


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
    kty = 'OKP'
    REQUIRED_JSON_FIELDS = ['crv', 'x']
    RAW_KEY_CLS = (
        Ed25519PublicKey, Ed25519PrivateKey,
        Ed448PublicKey, Ed448PrivateKey,
        X25519PublicKey, X25519PrivateKey,
        X448PublicKey, X448PrivateKey,
    )

    def get_op_key(self, key_op):
        return self.raw_key

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
        return {'x': to_unicode(urlsafe_b64encode(x_bytes))}

    @classmethod
    def import_key(cls, raw, options=None):
        return import_key(
            cls, raw,
            PUBLIC_KEY_TUPLE, PRIVATE_KEY_TUPLE,
            b'ecdsa-sha2-', options
        )

    @classmethod
    def generate_key(cls, crv, options=None, is_private=False):
        pass
