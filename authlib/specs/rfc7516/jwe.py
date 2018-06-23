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


class JWEContentAlgorithm(object):
    def encrypt(self, msg, aad, key):
        """Encrypt the given "msg" text.

        :param msg: text to be encrypt in bytes
        :param aad: additional authenticated data in bytes
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
