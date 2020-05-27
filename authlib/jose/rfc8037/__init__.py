from .okp_key import OKPKey
from ._jws_cryptography import EdDSAAlgorithm
JWS_ALGORITHMS = [EdDSAAlgorithm()]


__all__ = ['JWS_ALGORITHMS', 'OKPKey']
