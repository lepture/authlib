"""
    authlib.jose
    ~~~~~~~~~~~~

    JOSE implementation in Authlib. Tracking the status of JOSE specs at
    https://tools.ietf.org/wg/jose/
"""

from .rfc7515 import (
    JWS, JsonWebSignature, JWSAlgorithm, JWSHeader, JWSObject,
)
from .rfc7516 import (
    JWE, JsonWebEncryption, JWEAlgorithm, JWEEncAlgorithm, JWEZipAlgorithm,
)
from .rfc7517 import JWK, JsonWebKey, JWKAlgorithm
from .rfc7518 import (
    JWS_ALGORITHMS,
    JWE_ALGORITHMS,
    JWE_ALG_ALGORITHMS,
    JWE_ENC_ALGORITHMS,
    JWE_ZIP_ALGORITHMS,
    JWK_ALGORITHMS,
)
from .rfc7519 import JWT, JsonWebToken, BaseClaims, JWTClaims
from .jwk import jwk

jwt = JsonWebToken()


__all__ = [
    'JWS', 'JsonWebSignature', 'JWSAlgorithm', 'JWSHeader', 'JWSObject',
    'JWE', 'JsonWebEncryption', 'JWEAlgorithm', 'JWEEncAlgorithm', 'JWEZipAlgorithm',

    'JWK', 'JsonWebKey', 'JWKAlgorithm',

    'JWS_ALGORITHMS',
    'JWE_ALGORITHMS',
    'JWE_ALG_ALGORITHMS',
    'JWE_ENC_ALGORITHMS',
    'JWE_ZIP_ALGORITHMS',
    'JWK_ALGORITHMS',

    'JWT', 'JsonWebToken', 'BaseClaims', 'JWTClaims',
    'jwk', 'jwt',
]
