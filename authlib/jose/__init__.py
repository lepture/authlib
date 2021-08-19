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
from .rfc7517 import Key, KeySet, JsonWebKey
from .rfc7518 import (
    register_jws_rfc7518,
    register_jwe_rfc7518,
    ECDHESAlgorithm,
    OctKey,
    RSAKey,
    ECKey,
)
from .rfc7519 import JsonWebToken, BaseClaims, JWTClaims
from .rfc8037 import OKPKey, register_jws_rfc8037

from .errors import JoseError

# register algorithms
register_jws_rfc7518(JsonWebSignature)
register_jws_rfc8037(JsonWebSignature)

register_jwe_rfc7518(JsonWebEncryption)

# attach algorithms
ECDHESAlgorithm.ALLOWED_KEY_CLS = (ECKey, OKPKey)

# register supported keys
JsonWebKey.JWK_KEY_CLS = {
    OctKey.kty: OctKey,
    RSAKey.kty: RSAKey,
    ECKey.kty: ECKey,
    OKPKey.kty: OKPKey,
}

jwt = JsonWebToken()


__all__ = [
    'JoseError',

    'JsonWebSignature', 'JWSAlgorithm', 'JWSHeader', 'JWSObject',
    'JsonWebEncryption', 'JWEAlgorithm', 'JWEEncAlgorithm', 'JWEZipAlgorithm',

    'JsonWebKey', 'Key', 'KeySet',

    'OctKey', 'RSAKey', 'ECKey', 'OKPKey',

    'JsonWebToken', 'BaseClaims', 'JWTClaims',
    'jwt',
]
