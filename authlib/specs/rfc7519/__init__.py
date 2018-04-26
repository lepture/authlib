# -*- coding: utf-8 -*-
"""
    authlib.specs.rfc7519
    ~~~~~~~~~~~~~~~~~~~~~

    This module represents a direct implementation of
    JSON Web Token (JWT).

    https://tools.ietf.org/html/rfc7519
"""

from .jwt import JWT, jwk, jwt
from .claims import JWTClaims
from .errors import *


__all__ = [
    'JWT', 'jwk', 'jwt', 'JWTClaims', 'JWTError',
    'InvalidClaimError', 'MissingClaimError',
    'ExpiredTokenError', 'InvalidTokenError',
    'InsecureClaimError',
]
