from cryptography.x509 import load_pem_x509_certificate
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
        return load_key(key, b'ssh-rsa', key_type='public')


class ECKey(object):
    def prepare_private_key(self, key):
        if isinstance(key, EllipticCurvePrivateKey):
            return key
        key = to_bytes(key)
        return load_pem_private_key(key, password=None, backend=default_backend())

    def prepare_public_key(self, key):
        if isinstance(key, EllipticCurvePublicKey):
            return key
        return load_key(key, b'ecdsa-sha2-', key_type='public')


def load_key(key, ssh_type=None, key_type=None, password=None):
    key = to_bytes(key)

    if ssh_type and key.startswith(ssh_type):
        return load_ssh_public_key(key, backend=default_backend())

    if key_type == 'public':
        return load_pem_public_key(key, backend=default_backend())

    if key_type == 'private' or password is not None:
        return load_pem_private_key(key, password=password, backend=default_backend())

    if b'PUBLIC' in key:
        return load_pem_public_key(key, backend=default_backend())

    if b'PRIVATE' in key:
        return load_pem_private_key(key, password=password, backend=default_backend())

    if b'CERTIFICATE' in key:
        cert = load_pem_x509_certificate(key, default_backend())
        return cert.public_key()

    try:
        return load_pem_private_key(key, password=password, backend=default_backend())
    except ValueError:
        return load_pem_public_key(key, backend=default_backend())
