import os


class JWEAlgorithm(object):
    """Interface for JWE algorithm. JWA specification (RFC7518) SHOULD
    implement the algorithms for JWE with this base implementation.
    """
    EXTRA_HEADERS = None

    name = None
    description = None
    algorithm_type = 'JWE'
    algorithm_location = 'alg'

    def prepare_key(self, raw_data):
        raise NotImplementedError

    def wrap(self, enc_alg, headers, key, sender_key):
        raise NotImplementedError

    def unwrap(self, enc_alg, ek, headers, key, sender_key, tag):
        raise NotImplementedError


class JWEAlgorithmWithTagAwareKeyAgreement(JWEAlgorithm):
    """Interface for JWE algorithm with tag-aware key agreement (in key agreement with key wrapping mode).
    ECDH-1PU is an example of such an algorithm.
    """

    def generate_keys_and_prepare_headers(self, enc_alg, key, sender_key):
        raise NotImplementedError

    def agree_upon_key_and_wrap_cek(self, enc_alg, headers, key, sender_key, epk, cek, tag):
        raise NotImplementedError


class JWEEncAlgorithm(object):
    name = None
    description = None
    algorithm_type = 'JWE'
    algorithm_location = 'enc'

    IV_SIZE = None
    CEK_SIZE = None

    def generate_cek(self):
        return os.urandom(self.CEK_SIZE // 8)

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
        :return: (ciphertext, tag)
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
    name = None
    description = None
    algorithm_type = 'JWE'
    algorithm_location = 'zip'

    def compress(self, s):
        raise NotImplementedError

    def decompress(self, s):
        raise NotImplementedError
