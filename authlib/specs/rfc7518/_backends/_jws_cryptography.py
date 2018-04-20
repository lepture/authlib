# -*- coding: utf-8 -*-
"""
    authlib.specs.rfc7518
    ~~~~~~~~~~~~~~~~~~~~~

    "alg" (Algorithm) Header Parameter Values for JWS per `Section 3`_.

    .. _`Section 3`: https://tools.ietf.org/html/rfc7518#section-3
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, load_pem_public_key, load_ssh_public_key
)
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey, RSAPublicKey
)
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey, EllipticCurvePublicKey, ECDSA
)
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature, encode_dss_signature
)
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from authlib.specs.rfc7515 import JWSAlgorithm
from authlib.common.encoding import to_bytes
from ..utils import encode_int, decode_int


class RSAAlgorithm(JWSAlgorithm):
    """RSA using SHA algorithms for JWS. Available algorithms:

    - RS256: RSASSA-PKCS1-v1_5 using SHA-256
    - RS384: RSASSA-PKCS1-v1_5 using SHA-384
    - RS512: RSASSA-PKCS1-v1_5 using SHA-512
    """
    SHA256 = hashes.SHA256
    SHA384 = hashes.SHA384
    SHA512 = hashes.SHA512

    def __init__(self, hash_alg):
        self.hash_alg = hash_alg

    def prepare_sign_key(self, key):
        if isinstance(key, RSAPrivateKey):
            return key
        key = to_bytes(key)
        return load_pem_private_key(key, password=None, backend=default_backend())

    def prepare_verify_key(self, key):
        if isinstance(key, RSAPublicKey):
            return key
        key = to_bytes(key)
        if key.startswith(b'ssh-rsa'):
            return load_ssh_public_key(key, backend=default_backend())
        else:
            return load_pem_public_key(key, backend=default_backend())

    def sign(self, msg, key):
        return key.sign(msg, padding.PKCS1v15(), self.hash_alg())

    def verify(self, msg, key, sig):
        try:
            key.verify(sig, msg, padding.PKCS1v15(), self.hash_alg())
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

    def __init__(self, hash_alg):
        self.hash_alg = hash_alg

    def prepare_sign_key(self, key):
        if isinstance(key, EllipticCurvePrivateKey):
            return key
        key = to_bytes(key)
        return load_pem_private_key(key, password=None, backend=default_backend())

    def prepare_verify_key(self, key):
        if isinstance(key, EllipticCurvePublicKey):
            return key
        if key.startswith(b'ecdsa-sha2-'):
            return load_ssh_public_key(key, backend=default_backend())
        return load_pem_public_key(key, backend=default_backend())

    def sign(self, msg, key):
        der_sig = key.sign(msg, ECDSA(self.hash_alg()))
        r, s = decode_dss_signature(der_sig)
        size = key.curve.key_size
        return encode_int(r, size) + encode_int(s, size)

    def verify(self, msg, key, sig):
        key_size = key.curve.key_size
        length = (key_size + 7) // 8

        if len(sig) != 2 * length:
            return False

        r = decode_int(sig[:length])
        s = decode_int(sig[length:])
        der_sig = encode_dss_signature(r, s)

        try:
            key.verify(der_sig, msg, ECDSA(self.hash_alg()))
            return True
        except InvalidSignature:
            return False


class RSAPSSAlgorithm(RSAAlgorithm):
    """RSASSA-PSS using SHA algorithms for JWS. Available algorithms:

    - PS256: RSASSA-PSS using SHA-256 and MGF1 with SHA-256
    - PS384: RSASSA-PSS using SHA-384 and MGF1 with SHA-384
    - PS512: RSASSA-PSS using SHA-512 and MGF1 with SHA-512
    """
    def sign(self, msg, key):
        return key.sign(
            msg,
            padding.PSS(
                mgf=padding.MGF1(self.hash_alg()),
                salt_length=self.hash_alg.digest_size
            ),
            self.hash_alg()
        )

    def verify(self, msg, key, sig):
        try:
            key.verify(
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


JWS_ALGORITHMS = {
    'RS256': RSAAlgorithm(RSAAlgorithm.SHA256),
    'RS384': RSAAlgorithm(RSAAlgorithm.SHA384),
    'RS512': RSAAlgorithm(RSAAlgorithm.SHA512),
    'ES256': ECAlgorithm(ECAlgorithm.SHA256),
    'ES384': ECAlgorithm(ECAlgorithm.SHA384),
    'ES512': ECAlgorithm(ECAlgorithm.SHA512),
    'PS256': RSAPSSAlgorithm(RSAPSSAlgorithm.SHA256),
    'PS384': RSAPSSAlgorithm(RSAPSSAlgorithm.SHA384),
    'PS512': RSAPSSAlgorithm(RSAPSSAlgorithm.SHA512)
}
