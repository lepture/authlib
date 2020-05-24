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
from ..rfc7517 import JWKAlgorithm
from ..rfc7518._backends._key_cryptography import load_key

CURVES_KEYS = {
    'Ed25519': (Ed25519PublicKey, Ed25519PrivateKey),
    'Ed448': (Ed448PublicKey, Ed448PrivateKey),
    'X25519': (X25519PublicKey, X25519PrivateKey),
    'X448': (X448PublicKey, X448PrivateKey),
}


class OKPAlgorithm(JWKAlgorithm):
    name = 'OKP'
    key_cls = (
        Ed25519PublicKey, Ed25519PrivateKey,
        Ed448PublicKey, Ed448PrivateKey,
        X25519PublicKey, X25519PrivateKey,
        X448PublicKey, X448PrivateKey,
    )

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

    def prepare_key(self, key):
        return load_key(key, b'ssh-ed25519')

    def loads(self, obj):
        for k in ['crv', 'x']:
            if k not in obj:
                raise ValueError('Not a elliptic curve key')

        crv = obj['crv']
        if crv not in CURVES_KEYS:
            raise ValueError('Unsupported crv for OKP')
        keys = CURVES_KEYS[crv]

        # The parameter "d" MUST be present for private keys
        if 'd' in obj:
            crv_key = keys[1]
            d_bytes = urlsafe_b64decode(to_bytes(obj['d']))
            return crv_key.from_private_bytes(d_bytes)

        crv_key = keys[0]
        x_bytes = urlsafe_b64decode(to_bytes(obj['x']))
        return crv_key.from_public_bytes(x_bytes)

    def dumps(self, key):
        crv = self.get_key_curve(key)
        if not crv:
            raise ValueError('Unsupported key for OKP')
        if hasattr(key, 'private_bytes'):
            obj = self.dumps_private_key(key)
        else:
            obj = self.dumps_public_key(key)

        obj['crv'] = crv
        obj['kty'] = self.name
        return obj

    @staticmethod
    def dumps_private_key(key):
        obj = OKPAlgorithm.dumps_public_key(key.public_key())
        d_bytes = key.private_bytes(
            Encoding.Raw,
            PrivateFormat.Raw,
            NoEncryption()
        )
        obj['d'] = to_unicode(urlsafe_b64encode(d_bytes))
        return obj

    @staticmethod
    def dumps_public_key(key):
        x_bytes = key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return {'x': to_unicode(urlsafe_b64encode(x_bytes))}
