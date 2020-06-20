# -*- coding: utf-8 -*-
"""
    authlib.jose.rfc7518
    ~~~~~~~~~~~~~~~~~~~~

    "alg" (Algorithm) Header Parameter Values for JWS per `Section 3`_.

    .. _`Section 3`: https://tools.ietf.org/html/rfc7518#section-3
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature, encode_dss_signature
)
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from authlib.jose.rfc7515 import JWSAlgorithm
from ._keys import RSAKey, ECKey
from ..util import encode_int, decode_int


class RSAAlgorithm(JWSAlgorithm):
    """RSA using SHA algorithms for JWS. Available algorithms:

    - RS256: RSASSA-PKCS1-v1_5 using SHA-256
    - RS384: RSASSA-PKCS1-v1_5 using SHA-384
    - RS512: RSASSA-PKCS1-v1_5 using SHA-512
    """
    SHA256 = hashes.SHA256
    SHA384 = hashes.SHA384
    SHA512 = hashes.SHA512

    def __init__(self, sha_type):
        self.name = 'RS{}'.format(sha_type)
        self.description = 'RSASSA-PKCS1-v1_5 using SHA-{}'.format(sha_type)
        self.hash_alg = getattr(self, 'SHA{}'.format(sha_type))
        self.padding = padding.PKCS1v15()

    def prepare_key(self, raw_data):
        return RSAKey.import_key(raw_data)

    def sign(self, msg, key):
        op_key = key.get_op_key('sign')
        return op_key.sign(msg, self.padding, self.hash_alg())

    def verify(self, msg, sig, key):
        op_key = key.get_op_key('verify')
        try:
            op_key.verify(sig, msg, self.padding, self.hash_alg())
            return True
        except InvalidSignature:
            return False


class ECAlgorithm(JWSAlgorithm):
    """ECDSA using SHA algorithms for JWS. Available algorithms:

    - ES256: ECDSA using P-256 and SHA-256
    - ES384: ECDSA using P-384 and SHA-384
    - ES512: ECDSA using P-521 and SHA-512
    """
    SHA256 = hashes.SHA256
    SHA384 = hashes.SHA384
    SHA512 = hashes.SHA512

    def __init__(self, sha_type):
        self.name = 'ES{}'.format(sha_type)
        self.description = 'ECDSA using P-{} and SHA-{}'.format(sha_type, sha_type)
        self.hash_alg = getattr(self, 'SHA{}'.format(sha_type))

    def prepare_key(self, raw_data):
        return ECKey.import_key(raw_data)

    def sign(self, msg, key):
        op_key = key.get_op_key('sign')
        der_sig = op_key.sign(msg, ECDSA(self.hash_alg()))
        r, s = decode_dss_signature(der_sig)
        size = key.curve_key_size
        return encode_int(r, size) + encode_int(s, size)

    def verify(self, msg, sig, key):
        key_size = key.curve_key_size
        length = (key_size + 7) // 8

        if len(sig) != 2 * length:
            return False

        r = decode_int(sig[:length])
        s = decode_int(sig[length:])
        der_sig = encode_dss_signature(r, s)

        try:
            op_key = key.get_op_key('verify')
            op_key.verify(der_sig, msg, ECDSA(self.hash_alg()))
            return True
        except InvalidSignature:
            return False


class RSAPSSAlgorithm(JWSAlgorithm):
    """RSASSA-PSS using SHA algorithms for JWS. Available algorithms:

    - PS256: RSASSA-PSS using SHA-256 and MGF1 with SHA-256
    - PS384: RSASSA-PSS using SHA-384 and MGF1 with SHA-384
    - PS512: RSASSA-PSS using SHA-512 and MGF1 with SHA-512
    """
    SHA256 = hashes.SHA256
    SHA384 = hashes.SHA384
    SHA512 = hashes.SHA512

    def __init__(self, sha_type):
        self.name = 'PS{}'.format(sha_type)
        tpl = 'RSASSA-PSS using SHA-{} and MGF1 with SHA-{}'
        self.description = tpl.format(sha_type, sha_type)
        self.hash_alg = getattr(self, 'SHA{}'.format(sha_type))

    def prepare_key(self, raw_data):
        return RSAKey.import_key(raw_data)

    def sign(self, msg, key):
        op_key = key.get_op_key('sign')
        return op_key.sign(
            msg,
            padding.PSS(
                mgf=padding.MGF1(self.hash_alg()),
                salt_length=self.hash_alg.digest_size
            ),
            self.hash_alg()
        )

    def verify(self, msg, sig, key):
        op_key = key.get_op_key('verify')
        try:
            op_key.verify(
                sig,
                msg,
                padding.PSS(
                    mgf=padding.MGF1(self.hash_alg()),
                    salt_length=self.hash_alg.digest_size
                ),
                self.hash_alg()
            )
            return True
        except InvalidSignature:
            return False


JWS_ALGORITHMS = [
    RSAAlgorithm(256),  # RS256
    RSAAlgorithm(384),  # RS384
    RSAAlgorithm(512),  # RS512
    ECAlgorithm(256),  # ES256
    ECAlgorithm(384),  # ES384
    ECAlgorithm(512),  # ES512
    RSAPSSAlgorithm(256),  # PS256
    RSAPSSAlgorithm(384),  # PS384
    RSAPSSAlgorithm(512),  # PS512
]
