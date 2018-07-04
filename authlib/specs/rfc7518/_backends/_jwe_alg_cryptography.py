from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from authlib.specs.rfc7516 import JWEAlgorithm
from ._key_cryptography import RSAKey


class RSAAlgorithm(RSAKey, JWEAlgorithm):
    #: A key of size 2048 bits or larger MUST be used with these algorithms
    #: RSA1_5, RSA-OAEP, RSA-OAEP-256
    key_size = 2048

    def __init__(self, name, pad_fn):
        self.name = name
        self.padding = pad_fn

    def wrap(self, cek, headers, key):
        if key.key_size < self.key_size:
            raise ValueError('A key of size 2048 bits or larger MUST be used')
        ek = key.encrypt(cek, self.padding)
        return ek

    def unwrap(self, ek, headers, key):
        return key.decrypt(ek, self.padding)


JWE_ALGORITHMS = {
    'RSA1_5': RSAAlgorithm('RSA1_5', padding.PKCS1v15()),
    'RSA-OAEP': RSAAlgorithm(
        'RSA-OAEP',
        padding.OAEP(padding.MGF1(hashes.SHA1()), hashes.SHA1(), None)),
    'RSA-OAEP-256': RSAAlgorithm(
        'RSA-OAEP-256',
        padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)),
    'A128KW': '',
    'A192KW': '',
    'A256KW': '',
    'dir': '',
    'ECDH-ES': '',
    'ECDH-ES+A128KW': '',
    'ECDH-ES+A192KW': '',
    'ECDH-ES+A256KW': '',
    'A128GCMKW': '',
    'A192GCMKW': '',
    'A256GCMKW': '',
    'PBES2-HS256+A128KW': '',
    'PBES2-HS384+A192KW': '',
    'PBES2-HS512+A256KW': '',
}
