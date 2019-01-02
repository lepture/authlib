# -*- coding: utf-8 -*-
"""
    authlib.specs.rfc7518
    ~~~~~~~~~~~~~~~~~~~~~

    This module represents a direct implementation of
    JSON Web Algorithms (JWA).

    https://tools.ietf.org/html/rfc7518
"""

from .jws_algorithms import JWS_ALGORITHMS
from .jwe_algorithms import (
    JWE_ALGORITHMS,
    JWE_ALG_ALGORITHMS,
    JWE_ENC_ALGORITHMS,
    JWE_ZIP_ALGORITHMS,
)
from .jwk_algorithms import JWK_ALGORITHMS


__all__ = [
    'JWS_ALGORITHMS',
    'JWE_ALGORITHMS',
    'JWE_ALG_ALGORITHMS',
    'JWE_ENC_ALGORITHMS',
    'JWE_ZIP_ALGORITHMS',
    'JWK_ALGORITHMS'
]
