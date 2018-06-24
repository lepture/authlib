import os
from authlib.common.encoding import (
    to_bytes,
)
from ..rfc7515.util import (
    extract_header,
    extract_segment,
)
from .errors import (
    DecodeError,
    MissingAlgorithmError,
    UnsupportedAlgorithmError,
    MissingEncryptionAlgorithmError,
    UnsupportedEncryptionAlgorithmError,
    UnsupportedCompressionAlgorithmError,
    InvalidHeaderParameterName,
)


class JWEAlgorithm(object):
    """Interface for JWE algorithm. JWA specification (RFC7518) SHOULD
    implement the algorithms for JWE with this base implementation.
    """
    def prepare_private_key(self, key):
        raise NotImplementedError

    def prepare_public_key(self, key):
        raise NotImplementedError

    def wrap(self, key, bit_size, cek, headers):
        raise NotImplementedError

    def unwrap(self, key, bit_size, ek, headers):
        raise NotImplementedError


class JWEEncAlgorithm(object):
    IV_SIZE = 96

    def generate_iv(self):
        return os.urandom(self.IV_SIZE // 8)

    def check_iv(self, iv):
        if len(iv) * 8 != self.IV_SIZE:
            raise ValueError('Invalid "iv" size')

    def encrypt(self, msg, aad, iv, key):
        """Encrypt the given "msg" text.

        :param msg: text to be encrypt in bytes
        :param aad: additional authenticated data in bytes
        :param iv: initialization vector in bytes
        :param key: encrypted key in bytes
        :return: (ciphertext, iv, tag)
        """
        raise NotImplementedError

    def decrypt(self, ciphertext, aad, iv, tag, key):
        """Decrypt the given cipher text.

        :param ciphertext: ciphertext in bytes
        :param aad: additional authenticated data in bytes
        :param iv: initialization vector in bytes
        :param tag: authentication tag in bytes
        :param key: encrypted key in bytes
        :return: message
        """
        raise NotImplementedError


class JWEZipAlgorithm(object):
    def compress(self, plaintext):
        raise NotImplementedError

    def decompress(self, s):
        raise NotImplementedError


class JWE(object):
    #: Registered Header Parameter Names defined by `Section 4.1`_
    REGISTERED_HEADER_PARAMETER_NAMES = frozenset([
        'alg', 'enc', 'zip',
        'jku', 'jwk', 'kid',
        'x5u', 'x5c', 'x5t', 'x5t#S256',
        'typ', 'cty', 'crit'
    ])

    def __init__(self, algorithms, enc_algorithms, zip_algorithms, private_headers=None):
        self._algorithms = algorithms
        self._enc_algorithms = enc_algorithms
        self._zip_algorithms = zip_algorithms
        self._private_headers = private_headers

    def deserialize_compact(self, s, key):
        try:
            s = to_bytes(s)
            header_s, enc_key_s, iv_s, ciphertext_s, tag_s = s.rsplit(b'.')
        except ValueError:
            raise DecodeError('Not enough segments')

        header = extract_header(header_s, DecodeError)
        enc_key = extract_segment(enc_key_s, DecodeError, 'encryption key')
        iv = extract_segment(iv_s, DecodeError, 'initialization vector')
        ciphertext = extract_segment(ciphertext_s, DecodeError, 'ciphertext')
        tag = extract_segment(tag_s, DecodeError, 'authentication tag')
        self._validate_header(header)

    def deserialize_json(self, s, key):
        pass

    def deserialize(self, s, key):
        pass

    def _compress_text(self, s, header):
        pass

    def _decompress_text(self, s, header):
        pass

    def _validate_header(self, header):
        if 'alg' not in header:
            raise MissingAlgorithmError()

        alg = header['alg']
        if alg not in self._algorithms:
            raise UnsupportedAlgorithmError()

        if 'enc' not in header:
            raise MissingEncryptionAlgorithmError()

        enc = header['enc']
        if enc not in self._enc_algorithms:
            raise UnsupportedEncryptionAlgorithmError()

        zip = header.get('zip')
        if zip and zip not in self._zip_algorithms:
            raise UnsupportedCompressionAlgorithmError()

        names = self.REGISTERED_HEADER_PARAMETER_NAMES.copy()
        if self._private_headers:
            names = names.union(self._private_headers)

        for k in header:
            if k not in names:
                raise InvalidHeaderParameterName(k)
