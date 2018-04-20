try:
    from ._jwk_cryptography import JWK_ALGORITHMS
except ImportError:
    JWK_ALGORITHMS = {}

try:
    from ._jws_cryptography import JWS_ALGORITHMS
except ImportError:
    JWS_ALGORITHMS = {}
