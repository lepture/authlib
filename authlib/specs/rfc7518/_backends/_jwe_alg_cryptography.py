import os
from authlib.specs.rfc7516 import JWEAlgorithm
from ._key_cryptography import RSAKey


class RSAAlgorithm(RSAKey, JWEAlgorithm):
    key_size = 2048

    def __init__(self, name, padding):
        self.name = name
        self.padding = padding

    def wrap(self, cek, headers, key):
        if key.key_size < self.key_size:
            raise ValueError('TODO')
        ek = key.encrypt(cek, self.padding)
        return ek

    def unwrap(self, ek, headers, key):
        cek = key.decrypt(ek, self.padding)
        return cek


JWE_ALGORITHMS = {
    'RSA1_5': '',
    'RSA-OAEP': '',
    'RSA-OAEP-256': '',
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
