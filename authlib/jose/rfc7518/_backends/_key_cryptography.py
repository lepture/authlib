from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, load_pem_public_key, load_ssh_public_key
)
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey, RSAPublicKey
)
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey, EllipticCurvePublicKey
)
from cryptography.hazmat.backends import default_backend
from authlib.common.encoding import to_bytes


class RSAKey(object):
    def prepare_private_key(self, key):
        if isinstance(key, RSAPrivateKey):
            return key
        key = to_bytes(key)
        return load_pem_private_key(key, password=None, backend=default_backend())

    def prepare_public_key(self, key):
        if isinstance(key, RSAPublicKey):
            return key
        key = to_bytes(key)
        if key.startswith(b'ssh-rsa'):
            return load_ssh_public_key(key, backend=default_backend())
        else:
            return load_pem_public_key(key, backend=default_backend())


class ECKey(object):
    def prepare_private_key(self, key):
        if isinstance(key, EllipticCurvePrivateKey):
            return key
        key = to_bytes(key)
        return load_pem_private_key(key, password=None, backend=default_backend())

    def prepare_public_key(self, key):
        if isinstance(key, EllipticCurvePublicKey):
            return key
        if key.startswith(b'ecdsa-sha2-'):
            return load_ssh_public_key(key, backend=default_backend())
        return load_pem_public_key(key, backend=default_backend())
