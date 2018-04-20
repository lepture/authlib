# -*- coding: utf-8 -*-
"""
    authlib.specs.rfc7518.jws
    ~~~~~~~~~~~~~~~~~~~~~~~~~

    "alg" (Algorithm) Header Parameter Values for JWS per `Section 3`_.

    .. _`Section 3`: https://tools.ietf.org/html/rfc7518#section-3
"""

import hmac
import hashlib
from authlib.specs.rfc7515 import JWSAlgorithm
from authlib.common.encoding import to_bytes
from ._backends import JWS_ALGORITHMS


class NoneAlgorithm(JWSAlgorithm):
    def prepare_sign_key(self, key):
        return None

    def prepare_verify_key(self, key):
        return None

    def sign(self, msg, key):
        return b''

    def verify(self, msg, key, sig):
        return False


class HMACAlgorithm(JWSAlgorithm):
    """HMAC using SHA algorithms for JWS. Available algorithms:

    - HS256: HMAC using SHA-256
    - HS384: HMAC using SHA-384
    - HS512: HMAC using SHA-512
    """
    SHA256 = hashlib.sha256
    SHA384 = hashlib.sha384
    SHA512 = hashlib.sha512

    def __init__(self, hash_alg):
        self.hash_alg = hash_alg

    def prepare_sign_key(self, key):
        return to_bytes(key)

    def prepare_verify_key(self, key):
        key = to_bytes(key)
        return key

    def sign(self, msg, key):
        # it is faster than the one in cryptography
        return hmac.new(key, msg, self.hash_alg).digest()

    def verify(self, msg, key, sig):
        return hmac.compare_digest(sig, self.sign(msg, key))


JWS_ALGORITHMS.update({
    'none': NoneAlgorithm(),
    'HS256': HMACAlgorithm(HMACAlgorithm.SHA256),
    'HS384': HMACAlgorithm(HMACAlgorithm.SHA384),
    'HS512': HMACAlgorithm(HMACAlgorithm.SHA512),
})
