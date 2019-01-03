# -*- coding: utf-8 -*-
"""
    authlib.jose.rfc7519
    ~~~~~~~~~~~~~~~~~~~~

    This module represents a direct implementation of
    JSON Web Token (JWT).

    https://tools.ietf.org/html/rfc7519
"""

from .jwt import JWT
from .claims import JWTClaims


__all__ = ['JWT', 'JWTClaims']
