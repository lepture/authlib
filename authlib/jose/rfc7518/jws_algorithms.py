# -*- coding: utf-8 -*-
"""
    authlib.jose.rfc7518.jws_algorithms
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    "alg" (Algorithm) Header Parameter Values for JWS per `Section 3`_.

    .. _`Section 3`: https://tools.ietf.org/html/rfc7518#section-3
"""

import hmac
import hashlib
from .oct_key import OctKey
from ._cryptography_backends import JWS_ALGORITHMS
from ..rfc7515 import JWSAlgorithm, JsonWebSignature


class NoneAlgorithm(JWSAlgorithm):
    name = 'none'
    description = 'No digital signature or MAC performed'

    def prepare_key(self, raw_data):
        return None

    def sign(self, msg, key):
        return b''

    def verify(self, msg, sig, key):
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

    def __init__(self, sha_type):
        self.name = 'HS{}'.format(sha_type)
        self.description = 'HMAC using SHA-{}'.format(sha_type)
        self.hash_alg = getattr(self, 'SHA{}'.format(sha_type))

    def prepare_key(self, raw_data):
        return OctKey.import_key(raw_data)

    def sign(self, msg, key):
        # it is faster than the one in cryptography
        op_key = key.get_op_key('sign')
        return hmac.new(op_key, msg, self.hash_alg).digest()

    def verify(self, msg, sig, key):
        op_key = key.get_op_key('verify')
        v_sig = hmac.new(op_key, msg, self.hash_alg).digest()
        return hmac.compare_digest(sig, v_sig)


def register_jws_rfc7518():
    JsonWebSignature.register_algorithm(NoneAlgorithm())
    JsonWebSignature.register_algorithm(HMACAlgorithm(256))
    JsonWebSignature.register_algorithm(HMACAlgorithm(384))
    JsonWebSignature.register_algorithm(HMACAlgorithm(512))
    for algorithm in JWS_ALGORITHMS:
        JsonWebSignature.register_algorithm(algorithm)
