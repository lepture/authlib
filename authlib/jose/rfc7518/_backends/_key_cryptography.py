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
from authlib.jose.rfc7517 import Key
from authlib.common.encoding import to_bytes


class RSAKey(Key):
    kty = 'RSA'
    required_key_fields = ['e', 'n']

    private_key_cls = RSAPrivateKey
    public_key_cls = RSAPublicKey

    def get_supported_key_ops(self):
        if self.private_key:
            return ['sign', 'verify', 'wrapKey', 'unwrapKey']
        if self.public_key:
            return ['verify', 'wrapKey']
        return []

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
        return prepare_key(cls, raw_data, ssh_type=b'ssh-rsa', **params)


class ECKey(Key):
    kty = 'EC'
    required_key_fields = ['crv', 'x', 'y']

    private_key_cls = EllipticCurvePrivateKey
    public_key_cls = EllipticCurvePublicKey

    @property
    def curve_name(self):
        return self.key_data.curve.name

    @property
    def curve_key_size(self):
        return self.key_data.curve.key_size

    def get_supported_key_ops(self):
        if self.private_key:
            return ['sign', 'verify', 'wrapKey', 'unwrapKey']
        if self.public_key:
            return ['verify', 'wrapKey']
        return []

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
        return prepare_key(cls, raw_data, ssh_type=b'ecdsa-sha2-', **params)


def prepare_key(cls, raw_data, ssh_type=None, **params):
    if isinstance(raw_data, cls):
        raw_data.update(**params)
        return raw_data

    key = cls(raw_data, **params)
    if isinstance(raw_data, dict):
        key.check_key_fields(raw_data)
        key.dict_data = raw_data
    else:
        if isinstance(raw_data, cls.private_key_cls):
            key.key_data = raw_data
        elif isinstance(raw_data, cls.public_key_cls):
            key.key_data = raw_data
        else:
            key.key_data = load_pem_key(raw_data, ssh_type)
    return key


def load_pem_key(key, ssh_type=None, key_type=None, password=None):
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
