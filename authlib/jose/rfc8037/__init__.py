try:
    from ._jwk_cryptography import OKPAlgorithm
    JWK_ALGORITHMS = [OKPAlgorithm()]
except ImportError:
    JWK_ALGORITHMS = []
