# -*- coding: utf-8 -*-
"""
    authlib.specs.rfc7518
    ~~~~~~~~~~~~~~~~~~~~~

    This module represents a direct implementation of
    JSON Web Algorithms (JWA).

    https://tools.ietf.org/html/rfc7518
"""

from .jws_algorithms import JWS_ALGORITHMS
from .jwk_algorithms import JWK_ALGORITHMS

__all__ = ['JWS_ALGORITHMS', 'JWK_ALGORITHMS']
