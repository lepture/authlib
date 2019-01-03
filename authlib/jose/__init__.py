"""
    authlib.jose
    ~~~~~~~~~~~~

    JOSE implementation in Authlib. Tracking the status of JOSE specs at
    https://tools.ietf.org/wg/jose/
"""

from .rfc7515 import (
    JWS, JWSAlgorithm, JWSHeader, JWSObject,
)
from .rfc7516 import (
    JWE, JWEAlgorithm, JWEEncAlgorithm, JWEZipAlgorithm,
)
from .rfc7517 import JWK, JWKAlgorithm
from .rfc7518 import (
    JWS_ALGORITHMS,
    JWE_ALGORITHMS,
    JWE_ALG_ALGORITHMS,
    JWE_ENC_ALGORITHMS,
    JWE_ZIP_ALGORITHMS,
    JWK_ALGORITHMS,
)
from .rfc7519 import JWT, JWTClaims
from .jwk import jwk

jwt = JWT()


__all__ = [
    'JWS', 'JWSAlgorithm', 'JWSHeader', 'JWSObject',
    'JWE', 'JWEAlgorithm', 'JWEEncAlgorithm', 'JWEZipAlgorithm',
    'JWK', 'JWKAlgorithm',

    'JWS_ALGORITHMS',
    'JWE_ALGORITHMS',
    'JWE_ALG_ALGORITHMS',
    'JWE_ENC_ALGORITHMS',
    'JWE_ZIP_ALGORITHMS',
    'JWK_ALGORITHMS',

    'JWT', 'JWTClaims',
    'jwk', 'jwt',
]
