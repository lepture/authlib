from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey, EllipticCurvePublicKey
)
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey, RSAPublicKey
)

EC_TYPES = (EllipticCurvePrivateKey, EllipticCurvePublicKey)
RSA_TYPES = (RSAPrivateKey, RSAPublicKey)
