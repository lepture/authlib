from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
)
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey, Ed25519PrivateKey
)
from cryptography.hazmat.backends import default_backend
from authlib.common.encoding import to_bytes
from authlib.jose.rfc7515 import JWSAlgorithm
from ..rfc7518._backends._key_cryptography import load_key


class EdDSAAlgorithm(JWSAlgorithm):
    name = 'EdDSA'
    description = 'Edwards-curve Digital Signature Algorithm for JWS'
    private_key_cls = Ed25519PrivateKey
    public_key_cls = Ed25519PublicKey

    def prepare_private_key(self, key):
        key = to_bytes(key)
        return load_pem_private_key(key, password=None, backend=default_backend())

    def prepare_public_key(self, key):
        return load_key(key, b'ssh-ed25519', key_type='public')

    def sign(self, msg, key):
        return key.sign(msg)

    def verify(self, msg, key, sig):
        try:
            key.verify(sig, msg)
            return True
        except InvalidSignature:
            return False
