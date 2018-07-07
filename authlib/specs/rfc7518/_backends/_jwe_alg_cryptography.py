from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.keywrap import (
    aes_key_wrap,
    aes_key_unwrap
)
from authlib.common.encoding import to_bytes
from authlib.specs.rfc7516 import JWEAlgorithm
from ._key_cryptography import RSAKey


class RSAAlgorithm(RSAKey, JWEAlgorithm):
    #: A key of size 2048 bits or larger MUST be used with these algorithms
    #: RSA1_5, RSA-OAEP, RSA-OAEP-256
    key_size = 2048

    def __init__(self, name, pad_fn):
        super(RSAAlgorithm, self).__init__(name)
        self.padding = pad_fn

    def wrap(self, cek, headers, key):
        if key.key_size < self.key_size:
            raise ValueError('A key of size 2048 bits or larger MUST be used')
        ek = key.encrypt(cek, self.padding)
        return ek

    def unwrap(self, ek, headers, key):
        # it will raise ValueError if failed
        return key.decrypt(ek, self.padding)


class AESAlgorithm(JWEAlgorithm):
    def __init__(self, key_size):
        name = 'A{}KW'.format(key_size)
        super(AESAlgorithm, self).__init__(name)
        self.key_size = key_size

    def _check_key(self, key):
        if len(key) * 8 != self.key_size:
            raise ValueError(
                'A key of size {} bits is required.'.format(self.key_size))

    def prepare_private_key(self, key):
        return to_bytes(key)

    def prepare_public_key(self, key):
        return to_bytes(key)

    def wrap(self, cek, headers, key):
        self._check_key(key)
        ek = aes_key_wrap(key, cek, default_backend())
        return ek

    def unwrap(self, ek, headers, key):
        self._check_key(key)
        cek = aes_key_unwrap(key, ek, default_backend())
        return cek


JWE_ALG_ALGORITHMS = [
    RSAAlgorithm('RSA1_5', padding.PKCS1v15()),
    RSAAlgorithm(
        'RSA-OAEP',
        padding.OAEP(padding.MGF1(hashes.SHA1()), hashes.SHA1(), None)),
    RSAAlgorithm(
        'RSA-OAEP-256',
        padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)),
    AESAlgorithm(128),
    AESAlgorithm(192),
    AESAlgorithm(256),
]

# 'dir': '',
# 'ECDH-ES': '',
# 'ECDH-ES+A128KW': '',
# 'ECDH-ES+A192KW': '',
# 'ECDH-ES+A256KW': '',
# 'A128GCMKW': '',
# 'A192GCMKW': '',
# 'A256GCMKW': '',
# 'PBES2-HS256+A128KW': '',
# 'PBES2-HS384+A192KW': '',
# 'PBES2-HS512+A256KW': '',
