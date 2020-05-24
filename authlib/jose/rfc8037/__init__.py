try:
    from ._jwk_cryptography import OKPAlgorithm
    from ._jws_cryptography import EdDSAAlgorithm
    JWK_ALGORITHMS = [OKPAlgorithm()]
    JWS_ALGORITHMS = [EdDSAAlgorithm()]
except ImportError:
    JWK_ALGORITHMS = []
    JWS_ALGORITHMS = []

__all__ = ['JWK_ALGORITHMS', 'JWS_ALGORITHMS']
