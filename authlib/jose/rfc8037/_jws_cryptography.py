from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey, Ed25519PrivateKey
)
from authlib.jose.rfc7515 import JWSAlgorithm, JsonWebSignature
from .okp_key import OKPKey


class EdDSAAlgorithm(JWSAlgorithm):
    name = 'EdDSA'
    description = 'Edwards-curve Digital Signature Algorithm for JWS'
    private_key_cls = Ed25519PrivateKey
    public_key_cls = Ed25519PublicKey

    def prepare_key(self, raw_data):
        return OKPKey.import_key(raw_data)

    def sign(self, msg, key):
        op_key = key.get_op_key('sign')
        return op_key.sign(msg)

    def verify(self, msg, sig, key):
        op_key = key.get_op_key('verify')
        try:
            op_key.verify(sig, msg)
            return True
        except InvalidSignature:
            return False


def register_jws_rfc8037():
    JsonWebSignature.register_algorithm(EdDSAAlgorithm())
