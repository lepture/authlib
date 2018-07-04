try:
    from ._jws_cryptography import JWS_ALGORITHMS
except ImportError:
    JWS_ALGORITHMS = []

try:
    from ._jwe_alg_cryptography import JWE_ALG_ALGORITHMS
except ImportError:
    JWE_ALG_ALGORITHMS = []

try:
    from ._jwe_enc_cryptography import JWE_ENC_ALGORITHMS
except ImportError:
    JWE_ENC_ALGORITHMS = []

try:
    from ._jwk_cryptography import JWK_ALGORITHMS
except ImportError:
    JWK_ALGORITHMS = []
