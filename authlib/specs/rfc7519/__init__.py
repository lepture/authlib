# -*- coding: utf-8 -*-
"""
    authlib.specs.rfc7519
    ~~~~~~~~~~~~~~~~~~~~~

    This module represents a direct implementation of
    JSON Web Token (JWT).

    https://tools.ietf.org/html/rfc7519
"""

from .jwt import JWT
from .util import jwk
from .claims import JWTClaims
from .errors import *

jwt = JWT()

__all__ = [
    'JWT', 'jwk', 'jwt', 'JWTClaims', 'JWTError',
    'InvalidClaimError', 'MissingClaimError',
    'ExpiredTokenError', 'InvalidTokenError',
    'InsecureClaimError',
]
