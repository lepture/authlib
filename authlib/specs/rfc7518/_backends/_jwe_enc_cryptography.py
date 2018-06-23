"""
    authlib.specs.rfc7518
    ~~~~~~~~~~~~~~~~~~~~~

    Cryptographic Algorithms for Cryptographic Algorithms for Content
    Encryption per `Section 5`_.

    .. _`Section 5`: https://tools.ietf.org/html/rfc7518#section-5
"""
import os
import hmac
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import GCM, CBC
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.exceptions import InvalidTag
from authlib.specs.rfc7516 import JWEContentAlgorithm
from ..util import encode_int


class CBCHS2ContentAlgorithm(JWEContentAlgorithm):
    def __init__(self, key_size, hash_type):
        self.key_size = key_size
        self.key_bytes_length = key_size // 8
        self.wrap_key_size = key_size * 2
        self.hash_alg = getattr(hashlib, 'sha{}'.format(hash_type))

        self.name = 'A{}CBC-HS{}'.format(self.key_size, hash_type)

    def _hmac(self, ciphertext, aad, iv, key):
        al = encode_int(len(aad) * 8, 64)
        msg = aad + iv + ciphertext + al
        d = hmac.new(key, msg, self.hash_alg).digest()
        return d[:self.key_bytes_length]

    def encrypt(self, msg, aad, key):
        """Key Encryption with AES_CBC_HMAC_SHA2.

        :param msg: text to be encrypt in bytes
        :param aad: additional authenticated data in bytes
        :param key: encrypted key in bytes
        :return: (ciphertext, iv, tag)
        """
        hkey = key[:self.key_bytes_length]
        ekey = key[self.key_bytes_length:]

        iv = os.urandom(AES.block_size // 8)
        pad = PKCS7(AES.block_size).padder()
        padded_data = pad.update(msg) + pad.finalize()

        cipher = Cipher(AES(ekey), CBC(iv), backend=default_backend())
        enc = cipher.encryptor()
        ciphertext = enc.update(padded_data) + enc.finalize()
        tag = self._hmac(ciphertext, aad, iv, hkey)
        return ciphertext, iv, tag

    def decrypt(self, ciphertext, aad, iv, tag, key):
        """Key Decryption with AES AES_CBC_HMAC_SHA2.

        :param ciphertext: ciphertext in bytes
        :param aad: additional authenticated data in bytes
        :param iv: initialization vector in bytes
        :param tag: authentication tag in bytes
        :param key: encrypted key in bytes
        :return: message
        """
        hkey = key[:self.key_bytes_length]
        dkey = key[self.key_bytes_length:]

        _tag = self._hmac(ciphertext, aad, iv, hkey)
        if not hmac.compare_digest(_tag, tag):
            raise InvalidTag()

        cipher = Cipher(AES(dkey), CBC(iv), backend=default_backend())
        d = cipher.decryptor()
        data = d.update(ciphertext) + d.finalize()
        unpad = PKCS7(AES.block_size).unpadder()
        return unpad.update(data) + unpad.finalize()


class GCMContentAlgorithm(JWEContentAlgorithm):
    def __init__(self, key_size):
        self.name = 'A{}GCM'.format(self.key_size)
        self.key_size = key_size
        self.wrap_key_size = key_size

    def encrypt(self, msg, aad, key):
        """Key Encryption with AES GCM

        :param msg: text to be encrypt in bytes
        :param aad: additional authenticated data in bytes
        :param key: encrypted key in bytes
        :return: (ciphertext, iv, tag)
        """
        # 96-bit IV: 12 * 8 = 96
        # https://tools.ietf.org/html/rfc7518#section-4.7.1.1
        iv = os.urandom(12)
        cipher = Cipher(AES(key), GCM(iv), backend=default_backend())
        enc = cipher.encryptor()
        enc.authenticate_additional_data(aad)
        ciphertext = enc.update(msg) + enc.finalize()
        return ciphertext, iv, enc.tag

    def decrypt(self, ciphertext, aad, iv, tag, key):
        """Key Decryption with AES GCM

        :param ciphertext: ciphertext in bytes
        :param aad: additional authenticated data in bytes
        :param iv: initialization vector in bytes
        :param tag: authentication tag in bytes
        :param key: encrypted key in bytes
        :return: message
        """
        cipher = Cipher(AES(key), GCM(iv, tag), backend=default_backend())
        d = cipher.decryptor()
        d.authenticate_additional_data(aad)
        return d.update(ciphertext) + d.finalize()


JWE_ENCRYPTS = {
    'A128CBC-HS256': CBCHS2ContentAlgorithm(128, 256),
    'A192CBC-HS384': CBCHS2ContentAlgorithm(192, 384),
    'A256CBC-HS512': CBCHS2ContentAlgorithm(256, 512),
    'A128GCM': GCMContentAlgorithm(128),
    'A192GCM': GCMContentAlgorithm(192),
    'A256GCM': GCMContentAlgorithm(256),
}
