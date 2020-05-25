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
from ..rfc7517 import Key
from ..rfc7518._backends._key_cryptography import prepare_key

CURVES_KEYS = {
    'Ed25519': (Ed25519PublicKey, Ed25519PrivateKey),
    'Ed448': (Ed448PublicKey, Ed448PrivateKey),
    'X25519': (X25519PublicKey, X25519PrivateKey),
    'X448': (X448PublicKey, X448PrivateKey),
}


class OKPKey(Key):
    kty = 'OKP'
    required_key_fields = ['crv', 'x']
    private_key_cls = (Ed25519PrivateKey, Ed448PrivateKey, X25519PrivateKey, X448PrivateKey)
    public_key_cls = (Ed25519PublicKey, Ed448PublicKey, X25519PublicKey, X448PublicKey)

    @property
    def curve_name(self):
        key = self.key_data
        if isinstance(key, (Ed25519PublicKey, Ed25519PrivateKey)):
            return 'Ed25519'
        elif isinstance(key, (Ed448PublicKey, Ed448PrivateKey)):
            return 'Ed448'
        elif isinstance(key, (X25519PublicKey, X25519PrivateKey)):
            return 'X25519'
        elif isinstance(key, (X448PublicKey, X448PrivateKey)):
            return 'X448'

    def get_supported_key_ops(self):
        if isinstance(self.key_data, (Ed25519PrivateKey, Ed448PrivateKey)):
            return ['sign', 'verify']
        elif isinstance(self.key_data, (Ed25519PublicKey, Ed448PublicKey)):
            return ['verify']

    @property
    def private_key(self):
        if isinstance(self.key_data, self.private_key_cls):
            return self.key_data

    @property
    def public_key(self):
        if isinstance(self.key_data, self.public_key_cls):
            return self.key_data
        if isinstance(self.key_data, self.private_key_cls):
            return self.key_data.public_key()

    @classmethod
    def from_raw(cls, raw_data, **params):
        return prepare_key(cls, raw_data, b'ssh-ed25519', **params)

