"""
    authlib.jose.rfc7517
    ~~~~~~~~~~~~~~~~~~~~~

    This module represents a direct implementation of
    JSON Web Key (JWK).

    https://tools.ietf.org/html/rfc7517
"""
from .jwk import JsonWebKey, JWKAlgorithm


__all__ = ['JsonWebKey', 'JWKAlgorithm']
