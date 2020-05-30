"""
    authlib.jose
    ~~~~~~~~~~~~

    JOSE implementation in Authlib. Tracking the status of JOSE specs at
    https://tools.ietf.org/wg/jose/
"""

from .rfc7515 import (
    JsonWebSignature, JWSAlgorithm, JWSHeader, JWSObject,
)
from .rfc7516 import (
    JsonWebEncryption, JWEAlgorithm, JWEEncAlgorithm, JWEZipAlgorithm,
)
from .rfc7517 import Key, KeySet
from .rfc7518 import (
    JWS_ALGORITHMS,
    JWE_ALGORITHMS,
    JWE_ALG_ALGORITHMS,
    JWE_ENC_ALGORITHMS,
    JWE_ZIP_ALGORITHMS,
    OctKey,
    RSAKey,
    ECKey,
)
from .rfc7519 import JsonWebToken, BaseClaims, JWTClaims
from .rfc8037 import (
    OKPKey,
    JWS_ALGORITHMS as RFC8037_JWS_ALGORITHMS,
)
from .jwk import JsonWebKey

# attach algorithms
JWS_ALGORITHMS = JWS_ALGORITHMS + RFC8037_JWS_ALGORITHMS
JsonWebSignature.JWS_AVAILABLE_ALGORITHMS = {alg.name: alg for alg in JWS_ALGORITHMS}
JsonWebEncryption.JWE_AVAILABLE_ALGORITHMS = {alg.name: alg for alg in JWE_ALGORITHMS}

# register supported keys
JsonWebKey.JWK_KEY_CLS = {
    OctKey.kty: OctKey,
    RSAKey.kty: RSAKey,
    ECKey.kty: ECKey,
    OKPKey.kty: OKPKey,
}

# compatible imports
JWS = JsonWebSignature
JWE = JsonWebEncryption
JWK = JsonWebKey
JWT = JsonWebToken

jwt = JsonWebToken()


__all__ = [
    'JWS', 'JsonWebSignature', 'JWSAlgorithm', 'JWSHeader', 'JWSObject',
    'JWE', 'JsonWebEncryption', 'JWEAlgorithm', 'JWEEncAlgorithm', 'JWEZipAlgorithm',

    'JWK', 'JsonWebKey', 'Key', 'KeySet',

    'JWS_ALGORITHMS',
    'JWE_ALGORITHMS',
    'JWE_ALG_ALGORITHMS',
    'JWE_ENC_ALGORITHMS',
    'JWE_ZIP_ALGORITHMS',

    'OctKey', 'RSAKey', 'ECKey', 'OKPKey',

    'JWT', 'JsonWebToken', 'BaseClaims', 'JWTClaims',
    'jwt',
]
