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
    register_jws_rfc7518,
    register_jwe_rfc7518,
    ECDHAlgorithm,
    OctKey,
    RSAKey,
    ECKey,
)
from .rfc7519 import JsonWebToken, BaseClaims, JWTClaims
from .rfc8037 import OKPKey, register_jws_rfc8037
from .drafts import register_jwe_draft

from .errors import JoseError
from .jwk import JsonWebKey

# register algorithms
register_jws_rfc7518()
register_jwe_rfc7518()
register_jws_rfc8037()
register_jwe_draft()

# attach algorithms
ECDHAlgorithm.ALLOWED_KEY_CLS = (ECKey, OKPKey)

# register supported keys
JsonWebKey.JWK_KEY_CLS = {
    OctKey.kty: OctKey,
    RSAKey.kty: RSAKey,
    ECKey.kty: ECKey,
    OKPKey.kty: OKPKey,
}

# compatible constants
JWS_ALGORITHMS = list(JsonWebSignature.ALGORITHMS_REGISTRY.keys())
JWE_ALG_ALGORITHMS = list(JsonWebEncryption.ALG_REGISTRY.keys())
JWE_ENC_ALGORITHMS = list(JsonWebEncryption.ENC_REGISTRY.keys())
JWE_ZIP_ALGORITHMS = list(JsonWebEncryption.ZIP_REGISTRY.keys())
JWE_ALGORITHMS = JWE_ALG_ALGORITHMS + JWE_ENC_ALGORITHMS + JWE_ZIP_ALGORITHMS

# compatible imports
JWS = JsonWebSignature
JWE = JsonWebEncryption
JWK = JsonWebKey
JWT = JsonWebToken

jwt = JsonWebToken()


__all__ = [
    'JoseError',

    'JWS', 'JsonWebSignature', 'JWSAlgorithm', 'JWSHeader', 'JWSObject',
    'JWE', 'JsonWebEncryption', 'JWEAlgorithm', 'JWEEncAlgorithm', 'JWEZipAlgorithm',

    'JWK', 'JsonWebKey', 'Key', 'KeySet',

    'OctKey', 'RSAKey', 'ECKey', 'OKPKey',

    'JWT', 'JsonWebToken', 'BaseClaims', 'JWTClaims',
    'jwt',
]
